package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// createS3Client initializes and returns an S3 client using the AWS SDK v2.
// It loads the default AWS configuration from the environment and sets the
// client to use path-style addressing, which is required for non-AWS
// S3-compatible services like LocalStack.
func createS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	return client, nil
}

// downloadObject attempts to download an object from the specified S3 bucket
// and key and saves it to the given destination path on the local filesystem.
//
// If the object does not exist (NoSuchKey), it logs the event and returns true
// with a nil error, indicating that the process should continue with an empty
// corpus. For all other errors, it returns false and the corresponding error.
func downloadObject(ctx context.Context, s3Client *s3.Client, bucket, key,
	destPath string, logger *slog.Logger) (bool, error) {

	// Ensure the corpus directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return false, fmt.Errorf("creating parent directories: %w", err)
	}

	// Attempt to download the corpus from S3
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			logger.Info("Corpus object not found. Starting with "+
				"empty corpus.", "s3Bucket", bucket, "key", key)
			return true, nil
		}
		return false, fmt.Errorf("downloading s3://%s/%s: %w", bucket,
			key, err)
	}
	defer func() {
		if err := result.Body.Close(); err != nil {
			logger.Error("Failed to close file", "error",
				err)
		}
	}()

	// Create destination file
	outFile, err := os.Create(destPath)
	if err != nil {
		return false, fmt.Errorf("creating local file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			logger.Error("Failed to close file", "error",
				err)
		}
	}()

	// Write the content to the local file
	n, err := io.Copy(outFile, result.Body)
	if err != nil {
		return false, fmt.Errorf("writing to local file: %w", err)
	}

	logger.Info("Downloaded object",
		"bytes", n,
		"s3Bucket", bucket,
		"key", key,
		"destPath", destPath)
	return false, nil
}

// uploadObject uploads the content of the provided buffer to the specified S3
// bucket and key.
//
// The buffer content is uploaded as an "application/zip" content type with the
// correct content length.
//
// If the upload fails, it returns a wrapped error describing the failure.
// On success, it logs the upload details using the provided logger.
func uploadObject(ctx context.Context, s3Client *s3.Client, bucket, key string,
	buf *bytes.Buffer, logger *slog.Logger) error {

	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          bytes.NewReader(buf.Bytes()),
		ContentLength: aws.Int64(int64(buf.Len())),
		ContentType:   aws.String("application/zip"),
	})
	if err != nil {
		return fmt.Errorf("uploading s3://%s/%s: %w", bucket, key, err)
	}
	logger.Info("Uploaded object to S3",
		"s3Bucket", bucket,
		"key", key,
		"bytes", buf.Len())
	return nil
}

// unzip extracts the contents of the zip archive specified by srcZip
// into the destination directory destDir.
//
// It preserves file permissions and directory structure.
// If the zip archive is empty, it logs a message and returns without error.
// Any error during extraction is wrapped and returned.
func unzip(srcZip, destDir string, logger *slog.Logger) error {
	r, err := zip.OpenReader(srcZip)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			logger.Error("Failed to close file", "error",
				err)
		}
	}()

	if len(r.File) == 0 {
		logger.Info("Zip archive is empty, skipping unzip.", "zipFile",
			srcZip)
		return nil
	}

	for _, f := range r.File {
		fullPath := filepath.Join(destDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fullPath, f.Mode()); err != nil {
				return fmt.Errorf("creating dir %q: %w",
					fullPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fullPath),
			0755); err != nil {
			return fmt.Errorf("creating parent dir for %q: %w",
				fullPath, err)
		}

		srcFile, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening zip file %q: %w", f.Name,
				err)
		}
		defer func() {
			if err := srcFile.Close(); err != nil {
				logger.Error("Failed to close file", "error",
					err)
			}
		}()

		destFile, err := os.OpenFile(fullPath,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("creating file %q: %w", fullPath, err)
		}
		defer func() {
			if err := destFile.Close(); err != nil {
				logger.Error("Failed to close file", "error",
					err)
			}
		}()

		if _, err := io.Copy(destFile, srcFile); err != nil {
			return fmt.Errorf("copying to file %q: %w", fullPath,
				err)
		}
	}

	logger.Info("Successfully extracted zip archive.", "zipFile", srcZip,
		"destination", destDir)
	return nil
}

// zipDir compresses the directory at srcDir into a ZIP archive and returns it
// as a bytes.Buffer.
//
// The directory structure and file permissions are preserved.
// It returns an error if any file cannot be read or written into the archive.
func zipDir(srcDir string, logger *slog.Logger) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	baseDir := filepath.Clean(srcDir)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo,
		walkErr error) error {

		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil || relPath == "." {
			return err
		}

		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			header := &zip.FileHeader{
				Name:   relPath + "/",
				Method: zip.Deflate,
			}
			header.SetMode(info.Mode())
			_, err := zw.CreateHeader(header)
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %q: %w", path, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error("Failed to close file", "error",
					err)
			}
		}()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate
		header.SetMode(info.Mode())

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	logger.Info("Directory zipped successfully.", "source", srcDir)
	return buf, nil
}

// zipUploadCorpus compresses the contents of unzipDir into a ZIP archive
// and uploads it to the specified S3 bucket and object key.
//
// It logs any errors encountered during zipping or uploading.
func zipUploadCorpus(ctx context.Context, s3Client *s3.Client, bucketName,
	objectKey, unzipDir string, logger *slog.Logger) {

	logger.Info("Starting ZIP and upload process",
		"source_dir", unzipDir,
		"bucket", bucketName,
		"object_key", objectKey,
	)

	buf, err := zipDir(unzipDir, logger)
	if err != nil {
		logger.Error("Zipping failed", "error", err)
		return
	}

	if err := uploadObject(ctx, s3Client, bucketName, objectKey, buf,
		logger); err != nil {
		logger.Error("Upload failed", "error", err)
		return
	}

	logger.Info("Successfully zipped and uploaded corpus",
		"bucket", bucketName,
		"object_key", objectKey,
	)
}
