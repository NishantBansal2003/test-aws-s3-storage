package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// cleanupWorkspace deletes the temp directory to reset the workspace state.
// Any errors encountered during removal are logged, but do not stop execution.
func cleanupWorkspace(logger *slog.Logger, cfg *Config) {
	// Since the cfg has path to project and corpus directory and we want to
	// remove its temporary parent direcory, so we will go back to its
	// parent directry
	parentDir := filepath.Dir(cfg.ProjectDir)
	if err := os.RemoveAll(parentDir); err != nil {
		logger.Error("workspace cleanup failed", "error", err)
	}
}

// EnsureDirExists creates the specified directory and all necessary parents if
// they do not exist. Returns an error if the directory cannot be created.
func EnsureDirExists(dirPath string) error {
	// Ensure the directory exists (creates parents as needed)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// SanitizeURL parses the given raw URL string and returns a sanitized version
// in which any user credentials (e.g., a GitHub Personal Access Token) are
// replaced with a placeholder ("*****"). This ensures that sensitive
// information is not exposed in logs or output. If the URL cannot be parsed,
// the original URL is returned.
func SanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If URL parsing fails, return the original URL.
		return rawURL
	}

	// Remove user info (username and password) if present.
	if parsed.User != nil {
		parsed.User = url.User("*****")
	}

	return parsed.String()
}

// calculateFuzzSeconds calculate per-target fuzz duration:
// (SyncFrequency * NumWorkers) / totalTargets.
func CalculateFuzzSeconds(syncFrequency time.Duration, numWorkers int,
	totalTargets int) float64 {

	return syncFrequency.Seconds() * float64(numWorkers) /
		float64(totalTargets)
}

// ComputeSHA256Short computes a SHA-256 hash of the concatenation of
// the given package name, fuzz target, and error data(*.go:<line>), then
// returns the first 16 characters of the hash.
//
// This function is designed to generate a short but unique signature string
// to identify and deduplicate GitHub issues caused by the same crash,
// helping to avoid opening multiple issues for identical errors.
func ComputeSHA256Short(pkg, fuzzTarget, errorData string) string {
	h := sha256.New()
	h.Write([]byte(pkg))
	h.Write([]byte(fuzzTarget))
	h.Write([]byte(errorData))
	hash := h.Sum(nil)

	return hex.EncodeToString(hash)[:16]
}

// FileExistsInDir checks whether a file with the specified name exists
// directly within the given directory (non-recursively).
func FileExistsInDir(dirPath, fileName string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() == fileName {
			return true, nil
		}
	}

	return false, nil
}
