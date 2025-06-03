package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	bucketName = "test-fuzz-bucket"
	objectKey  = "corpus.zip"

	localZipPath = "~/corpus.zip"
	unzipDir     = "~/corpus"
)

func main() {
	ctx := context.Background()
	s3Client, err := createS3Client(ctx)
	if err != nil {
		log.Fatalf("Failed to create S3 client: %v", err)
	}

	empty, err := downloadObject(ctx, s3Client, bucketName, objectKey, localZipPath)
	if err != nil {
		log.Fatalf("Download failed: %v", err)
	}

	if err := os.MkdirAll(unzipDir, 0755); err != nil {
		log.Fatalf("could not create destination directory %q: %v", unzipDir, err)
	}

	if !empty {
		if err := unzip(localZipPath, unzipDir); err != nil {
			log.Fatalf("Unzip failed: %v", err)
		}
	}

	buf, err := zipDir(unzipDir)
	if err != nil {
		log.Fatalf("Zipping failed: %v", err)
	}

	if err := uploadObject(ctx, s3Client, bucketName, objectKey, buf); err != nil {
		log.Fatalf("Upload failed: %v", err)
	}
}

func createS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true // Needed for non-AWS providers
	})
	return client, nil
}

func downloadObject(ctx context.Context, s3Client *s3.Client, bucket, key, destPath string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return false, fmt.Errorf("creating parent directories: %w", err)
	}

	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			log.Printf("📁 Object s3://%s/%s not found, continuing without error.\n", bucket, key)
			return true, nil
		}
		return false, fmt.Errorf("downloading s3://%s/%s: %w", bucket, key, err)
	}
	defer result.Body.Close()

	outFile, err := os.Create(destPath)
	if err != nil {
		return false, fmt.Errorf("creating local file: %w", err)
	}
	defer outFile.Close()

	n, err := io.Copy(outFile, result.Body)
	if err != nil {
		return false, fmt.Errorf("writing to local file: %w", err)
	}

	log.Printf("✅ Downloaded %d bytes to %s\n", n, destPath)
	return false, nil
}

func uploadObject(ctx context.Context, s3Client *s3.Client, bucket, key string, buf *bytes.Buffer) error {
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
	log.Printf("✅ Uploaded zip to s3://%s/%s\n", bucket, key)
	return nil
}

func unzip(srcZip, destDir string) error {
	r, err := zip.OpenReader(srcZip)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	if len(r.File) == 0 {
		log.Printf("📁 Zip %s is empty, skipping unzip.\n", srcZip)
		return nil
	}

	for _, f := range r.File {
		fullPath := filepath.Join(destDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fullPath, f.Mode()); err != nil {
				return fmt.Errorf("creating dir %q: %w", fullPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return fmt.Errorf("creating parent dir for %q: %w", fullPath, err)
		}

		srcFile, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening zip file %q: %w", f.Name, err)
		}
		defer srcFile.Close()

		destFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("creating file %q: %w", fullPath, err)
		}
		defer destFile.Close()

		if _, err := io.Copy(destFile, srcFile); err != nil {
			return fmt.Errorf("copying to file %q: %w", fullPath, err)
		}
	}
	return nil
}

func zipDir(srcDir string) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	baseDir := filepath.Clean(srcDir)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil || relPath == "." {
			return err
		}

		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			header := &zip.FileHeader{Name: relPath + "/", Method: zip.Deflate}
			header.SetMode(info.Mode())
			_, err := zw.CreateHeader(header)
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %q: %w", path, err)
		}
		defer file.Close()

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
	return buf, nil
}
