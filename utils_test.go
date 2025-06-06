package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSanitizeURL verifies that the sanitizeURL function correctly masks
// credentials in URLs. It ensures that URLs containing user credentials
// are sanitized by replacing them with asterisks, while URLs without
// credentials remain unchanged.
func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name                 string
		inputURL             string
		expectedSanitizedURL string
	}{
		{
			name: "url with credentials",
			inputURL: "https://user:pass@github.com/" +
				"OWNER/REPO.git",
			expectedSanitizedURL: "https://%2A%2A%2A%2A%2A@" +
				"github.com/OWNER/REPO.git",
		},
		{
			name: "url without credentials",
			inputURL: "https://github.com/OWNER/REPO" +
				".git",
			expectedSanitizedURL: "https://github.com/OWNER/REPO" +
				".git",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualSanitizedURL := SanitizeURL(tc.inputURL)
			assert.Equal(t, tc.expectedSanitizedURL,
				actualSanitizedURL, "Sanitized URL does not "+
					"match expected result")
		})
	}
}

// TestCalculateFuzzSeconds verifies that CalculateFuzzSeconds correctly
// computes the per-target fuzz duration given a sync frequency, number of
// parallel workers, and total number of fuzz targets.
func TestCalculateFuzzSeconds(t *testing.T) {
	// Parse a sample total fuzz time.
	syncFrequency, err := time.ParseDuration("3h37m53s")
	assert.NoError(t, err, "failed to parse syncFrequency")

	// Define the number of parallel workers and total targets.
	totalWorkers := 7
	totalTargets := 43

	// Compute the expected per-target fuzz duration.
	expectedDuration, err := time.ParseDuration("35m28s")
	assert.NoError(t, err, "failed to parse expectedDuration")

	seconds := CalculateFuzzSeconds(syncFrequency, totalWorkers,
		totalTargets)
	actualDuration := time.Duration(seconds) * time.Second

	assert.Equal(t, expectedDuration, actualDuration,
		"calculated fuzz duration does not match expected value",
	)
}

// TestComputeSHA256Short verifies that ComputeSHA256Short correctly computes a
// short SHA256 hash based on the package name, fuzz target, and error data.
// This test ensures that deduplication logic based on this hash remains stable
// and predictable.
func TestComputeSHA256Short(t *testing.T) {
	packageName := "parser"
	targetName := "FuzzParseComplex"
	errorData := "fuzz.go:322\nstringutils_test.go:17"

	expectedHash := "033fec7be7cb79a4"
	actualHash := ComputeSHA256Short(packageName, targetName,
		errorData)

	assert.Equal(t, expectedHash, actualHash, "Computed hash does not "+
		"match the expected value")
}
