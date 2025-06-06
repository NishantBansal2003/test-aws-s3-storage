package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// listPkgsFuzzTargets scans each package path listed in cfg.FuzzPkgsPath,
// invokes listFuzzTargets to retrieve fuzz targets for that package, and
// returns a map of package-to-targets along with the total number of fuzz
// targets found across all packages. If any package listing fails, it returns
// a non-nil error.
func listPkgsFuzzTargets(ctx context.Context, logger *slog.Logger,
	cfg *Config) (map[string][]string, int, error) {

	pkgToTargets := make(map[string][]string, len(cfg.FuzzPkgsPath))
	totalTargets := 0

	for _, pkgPath := range cfg.FuzzPkgsPath {
		targets, err := listFuzzTargets(ctx, logger, cfg, pkgPath)
		if err != nil {
			return nil, 0, fmt.Errorf(
				"failed to list fuzz targets for package "+
					"%q: %w", pkgPath, err,
			)
		}

		pkgToTargets[pkgPath] = targets
		count := len(targets)
		totalTargets += count
	}

	return pkgToTargets, totalTargets, nil
}

// listFuzzTargets discovers and returns a list of fuzz targets for the given
// package. It uses "go test -list=^Fuzz" to list the functions and filters
// those that start with "Fuzz".
func listFuzzTargets(ctx context.Context, logger *slog.Logger,
	cfg *Config, pkg string) ([]string, error) {

	logger.Info("Discovering fuzz targets", "package", pkg)

	// Construct the absolute path to the package directory within the
	// default project directory.
	pkgPath := filepath.Join(cfg.ProjectDir, pkg)

	// Prepare the command to list all test functions matching the pattern
	// "^Fuzz". This leverages go's testing tool to identify fuzz targets.
	cmd := exec.CommandContext(ctx, "go", "test", "-list=^Fuzz", ".")

	// Set the working directory to the package path.
	cmd.Dir = pkgPath

	// Initialize buffers to capture standard output and standard error from
	// the command execution.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command and check for errors, when the context wasn't
	// canceled.
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("go test failed for %q: %w (output: %q)",
			pkg, err, strings.TrimSpace(stderr.String()))
	}

	// targets holds the names of discovered fuzz targets.
	var targets []string

	// Process each line of the command's output.
	for _, line := range strings.Split(stdout.String(), "\n") {
		cleanLine := strings.TrimSpace(line)
		if strings.HasPrefix(cleanLine, "Fuzz") {
			// If the line represents a fuzz target, add it to the
			// list.
			targets = append(targets, cleanLine)
		}
	}

	// If no fuzz targets are found, log a warning to inform the user.
	if len(targets) == 0 {
		logger.Warn("No valid fuzz targets found", "package", pkg)
	}

	return targets, nil
}

// executeFuzzTarget runs the specified fuzz target for a package for a given
// duration using the "go test" command. It sets up the necessary environment,
// starts the command, streams its output, and logs any failures to a log file.
func executeFuzzTarget(ctx context.Context, logger *slog.Logger, pkg string,
	target string, cfg *Config, fuzzTime time.Duration) error {

	logger.Info("Executing fuzz target", "package", pkg, "target", target,
		"duration", fuzzTime)

	// Construct the absolute path to the package directory within the
	// default project directory.
	pkgPath := filepath.Join(cfg.ProjectDir, pkg)

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(cfg.CorpusDir, pkg, "testdata", "fuzz")

	// Define the path where failing corpus inputs might be saved by the
	// fuzzing process.
	maybeFailingCorpusPath := filepath.Join(pkgPath, "testdata", "fuzz")

	// Prepare the arguments for the 'go test' command to run the specific
	// fuzz target.
	args := []string{
		"test",
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusPath),
		fmt.Sprintf("-fuzztime=%s", fuzzTime),
		fmt.Sprintf("-parallel=1"),
	}

	// Initialize the 'go test' command with the specified arguments and
	// context.
	cmd := exec.CommandContext(ctx, "go", args...)
	// Set the working directory for the command.
	cmd.Dir = pkgPath

	// Obtain a pipe to read the standard output of the command.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe failed: %w", err)
	}

	// Start the execution of the 'go test' command.
	if err := cmd.Start(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("command start failed: %w", err)
	}

	// Channel to signal if the fuzz target encountered a failure.
	fuzzTargetFailingChan := make(chan bool, 1)

	// Stream and process the standard output of 'go test', which may
	// include both stdout and stderr content.
	streamFuzzOutput(logger.With("target", target).With("package", pkg),
		stdout, maybeFailingCorpusPath, cfg, pkg, target,
		fuzzTargetFailingChan, ctx)

	// Wait for the 'go test' command to finish execution.
	err = cmd.Wait()

	// Check if the fuzz target encountered a failure.
	isFailing := <-fuzzTargetFailingChan

	// Proceed to return an error only if the fuzz target did not fail
	// (i.e., no failure was detected during fuzzing), and the command
	// execution resulted in an error, and the error is not due to a
	// cancellation of the context.
	if err != nil {
		if ctx.Err() == nil && !isFailing {
			return fmt.Errorf("fuzz execution failed: %w", err)
		}
	}

	// If the fuzz target fails, 'go test' saves the failing input in the
	// package's testdata/fuzz/<FuzzTestName> directory. To prevent these
	// saved inputs from causing subsequent test runs to fail (especially
	// when running other fuzz targets), we remove the testdata directory to
	// clean up the failing inputs.
	if isFailing {
		failingInputPath := filepath.Join(pkgPath, "testdata", "fuzz",
			target)
		if err := os.RemoveAll(failingInputPath); err != nil {
			return fmt.Errorf("failing input cleanup failed: %w",
				err)
		}
	}

	logger.Info("Fuzzing completed successfully", "package", pkg,
		"target", target,
	)

	return nil
}

// streamFuzzOutput reads and processes the standard output of a fuzzing
// process. It utilizes a fuzzOutputProcessor to parse each line of output,
// identifying any errors or failures that occur during fuzzing. If a failure is
// detected, it logs the error details and the corresponding failing test case
// into the log file for analysis. The function signals completion through the
// provided WaitGroup and communicates whether a failure was encountered via the
// fuzzTargetFailingChan channel.
func streamFuzzOutput(logger *slog.Logger, r io.Reader,
	corpusPath string, cfg *Config, pkg string, target string,
	failureChan chan bool, ctx context.Context) {

	// Create a fuzzOutputProcessor to handle parsing and logging of fuzz
	// output.
	processor := NewFuzzOutputProcessor(logger, cfg, corpusPath, pkg,
		target, ctx)

	// Process the fuzzing output stream. This will log all output, detect
	// failures, and write failure details to disk if encountered.
	failureDetected := processor.processFuzzStream(r)

	// Communicate the result (failure detected or not) back to the caller.
	failureChan <- failureDetected
}
