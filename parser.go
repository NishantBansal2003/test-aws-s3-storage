package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// fuzzFailureRegex matches lines indicating a fuzzing failure or a
	// failing input, capturing the fuzz target name and the corresponding
	// input ID.
	//
	// It matches lines like:
	//   "Failing input written to testdata/fuzz/FuzzFoo/771e938e4458e983"
	//
	// Captured groups:
	//   - "target": the fuzz target name (e.g., "FuzzFoo")
	//   - "id": the hexadecimal input ID (e.g., "771e938e4458e983")
	fuzzFailureRegex = regexp.MustCompile(
		`Failing input written to testdata/fuzz/` +
			`(?P<target>[^/]+)/(?P<id>[0-9a-f]+)`,
	)

	// fuzzFileLineRegex matches a stack-trace line indicating a fuzzing
	// error, capturing the .go file name and line number.
	//
	// It matches lines like:
	//   "stringutils_test.go:17: Reverse produced invalid UTF-8 string"
	//
	// Captured groups:
	//   - "file": the .go file name (e.g., "stringutils_test.go")
	//   - "line": the line number (e.g., "17")
	fuzzFileLineRegex = regexp.MustCompile(
		`\s*(?P<file>[^/]+\.(?:go)):(?P<line>[0-9]+)`,
	)
)

// fuzzOutputProcessor handles parsing and logging of fuzzing output streams,
// detecting failures, and capturing/logging failing input data.
type fuzzOutputProcessor struct {
	ctx context.Context

	// Logger for informational and error messages.
	logger *slog.Logger

	// Configuration settings provided by the user
	cfg *Config

	// Directory containing the fuzzing corpus.
	corpusDir string

	// Name of the package under test.
	packageName string

	// Name of the fuzz target under test.
	targetName string

	// File handle for writing failure logs.
	logFile *os.File
}

// NewFuzzOutputProcessor constructs a fuzzOutputProcessor for the given logger,
// config, corpus directory, and fuzz target name.
func NewFuzzOutputProcessor(logger *slog.Logger, cfg *Config, corpusDir, pkg,
	targetName string, ctx context.Context) *fuzzOutputProcessor {

	return &fuzzOutputProcessor{
		ctx:         ctx,
		logger:      logger,
		cfg:         cfg,
		corpusDir:   corpusDir,
		packageName: pkg,
		targetName:  targetName,
	}
}

// processFuzzStream reads each line from the fuzzing output stream, logs all
// lines, and captures failure details if a failure is detected. Returns true if
// a failure was found and processed, false otherwise.
func (fp *fuzzOutputProcessor) processFuzzStream(stream io.Reader) bool {
	scanner := bufio.NewScanner(stream)

	// Scan until a failure line is found; if not found, return false.
	if !fp.scanUntilFailure(scanner) {
		return false
	}

	// Process and log failure lines, capturing error data.
	fp.processFailureLines(scanner)

	return true
}

// scanUntilFailure scans the output until a failure indicator (--- FAIL:) is
// found. Returns true if a failure line is detected, false otherwise.
func (fp *fuzzOutputProcessor) scanUntilFailure(scanner *bufio.Scanner) bool {
	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Detect the start of a failure section.
		if strings.Contains(line, "--- FAIL:") {
			return true
		}
	}
	return false
}

// processFailureLines processes lines after a failure is detected, writes them
// to a log file, and attempts to extract and log the failing input data.
func (fp *fuzzOutputProcessor) processFailureLines(scanner *bufio.Scanner) {
	var errorLog string
	var errorInput string
	var errorData string

	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Write the current line to the failure log.
		errorLog = errorLog + line + "\n"

		// errorData stores the .go file and line where an error
		// occurred for deduplication.
		// Parse the current error line to extract the .go file and line
		// then append them to errorData.
		errorFileAndLine := parseFileAndLine(line)
		if errorFileAndLine != "" {
			errorData = errorData + errorFileAndLine + "\n"
		}

		// If error data has already been captured, skip further
		// extraction.
		if errorInput != "" {
			continue
		}

		// Parse the line to extract the fuzz target and ID (hex) of the
		// failing input.
		// When a fuzz target encounters a failure during f.Add, the
		// crash is printed, but no input is saved to testdata/fuzz.
		//
		// The log output typically appears as:
		//   failure while testing seed corpus entry: FuzzFoo/seed#0
		//
		// As a result, no error data will be printed.
		target, id := parseFailureLine(line)
		// If either target or ID is empty, skip further processing.
		if target == "" || id == "" {
			continue
		}

		// Read and store the input data associated with the failing
		// target and ID.
		errorInput = fp.readFailingInput(target, id)
	}

	// Parse the URL to extract the token, owner, and repo
	parsedURL, err := url.Parse(fp.cfg.ProjectSrcPath)
	if err != nil {
		fp.logger.Error("Invalid repository URL", "error", err)
		return
	}

	// Extract the token to check if we have permission to open the GitHub
	// issue.
	token := extractToken(parsedURL)
	if token != "" {
		// A token is present, which means we have permission to open
		// the issue on GitHub.

		// Create GitHub client
		client := createGitHubClient(fp.ctx, token)

		owner, repo, err := extractOwnerRepo(parsedURL)
		if err != nil {
			fp.logger.Error("Error extracting owner and repo",
				"error", err)
			return
		}

		// Compute a short signature hash for the crash to help with
		// deduplication.
		crashHash := ComputeSHA256Short(fp.packageName, fp.targetName,
			errorData)

		title := fmt.Sprintf("[fuzz/%s] Fuzzing crash in %s", crashHash,
			fp.targetName)
		body := formatCrashReport(errorLog, errorInput)

		if !isIssueExist(fp.ctx, client, owner, repo, title,
			fp.logger) {

			if err := createIssue(fp.ctx, client, owner, repo,
				title, body, fp.logger); err != nil {
				fp.logger.Error("Failed to create GitHub issue",
					"error", err)
			}
		}

		return
	}

	fp.logger.Info("No permission to create a GitHub issue; logging "+
		"instead.", "logfile_path", fp.cfg.FuzzResultsPath)

	// Ensure the results directory exists.
	if err := EnsureDirExists(fp.cfg.FuzzResultsPath); err != nil {
		fp.logger.Error("Failed to create fuzz results directory",
			"error", err)
		return
	}

	// Check if the crash has already been recorded to avoid duplicate
	// logging.
	isKnown, logFileName, err := fp.isCrashDuplicate(errorData)
	if err != nil {
		fp.logger.Error("Failed to perform crash deduplication",
			"error", err)
		return
	}
	if isKnown {
		fp.logger.Info("Known crash detected. Please fix the failing "+
			"testcase.", "log_file", logFileName)
		return
	}

	// A new unique crash has been detected. Proceed to log the crash
	// details.
	if err := fp.writeCrashLog(logFileName, errorLog,
		errorInput); err != nil {
		fp.logger.Error("Failed to write crash log", "error", err)
		return
	}
}

// parseFileAndLine attempts to extract stack-trace line indicating a fuzzing
// error, capturing the .go file name and line number.
func parseFileAndLine(errorLine string) string {
	// Apply the regular expression to the line to find matches
	matches := fuzzFileLineRegex.FindStringSubmatch(errorLine)

	// Return empty strings if no match is found
	if matches == nil {
		return ""
	}

	var file, line string
	// Iterate over the named subexpressions to assign values of file and
	// line.
	for i, name := range fuzzFileLineRegex.SubexpNames() {
		switch name {
		case "file":
			file = matches[i]
		case "line":
			line = matches[i]
		}
	}
	return file + ":" + line
}

// isCrashDuplicate checks whether a crash with the same hash has already been
// logged. Returns true if the crash is already known, false otherwise, along
// with the generated log file name.
func (fp *fuzzOutputProcessor) isCrashDuplicate(errorData string) (bool,
	string, error) {

	// Compute a short signature hash for the crash to help with
	// deduplication.
	crashHash := ComputeSHA256Short(fp.packageName, fp.targetName,
		errorData)

	// Construct the log file name using the package, target name and crash
	// hash.
	logFileName := fmt.Sprintf("%s_%s_%s_failure.md", fp.packageName,
		fp.targetName, crashHash)

	// Check if a log file with the same signature already exists in the
	// fuzz results directory.
	isKnown, err := FileExistsInDir(fp.cfg.FuzzResultsPath, logFileName)
	if err != nil {
		return false, "", fmt.Errorf("checking for existing crash "+
			"log: %w", err)
	}

	return isKnown, logFileName, nil
}

// writeCrashLog creates and writes crash logs into a file at the given location
func (fp *fuzzOutputProcessor) writeCrashLog(logFileName, errorLog,
	errorInput string) error {

	// Construct the log file path for storing failure details.
	logPath := filepath.Join(fp.cfg.FuzzResultsPath, logFileName)

	// Create the log file for writing.
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	fp.logFile = logFile

	// Ensure the log file is closed at the end.
	defer func() {
		if err := fp.logFile.Close(); err != nil {
			fp.logger.Error("Failed to close log file", "error",
				err)
		}
	}()

	fp.logger.Info("Failure log initialized", "path", logPath)

	// Write the error logs to the failure log file.
	_, err = fp.logFile.WriteString(formatCrashReport(errorLog, errorInput))
	if err != nil {
		return fmt.Errorf("failed to write logs: %w", err)
	}

	return nil
}

// formatCrashReport constructs a markdown-formatted report containing the error
// logs, the failing test case (or a placeholder message if none is provided),
// and a watermark. If errorInput is empty, a generic failing-testcase message
// is used.
func formatCrashReport(errorLog, errorInput string) string {
	// Build the "Error logs" section.
	logSection := fmt.Sprintf("## Error logs\n~~~sh\n%s~~~", errorLog)

	// If we can't retrieve error data, the error likely originates from a
	// seed corpus entry in the form:
	//   "failure while testing seed corpus entry: FuzzFoo/771e938e4458e983"
	if errorInput == "" {
		errorInput = "\n## Failing testcase\n" +
			"Failure while testing seed corpus entry. " +
			"Please ensure your latest changes do not introduce " +
			"any bugs."
	}

	// Combine sections with the watermark at the end.
	return fmt.Sprintf("%s\n%s\n%s\n", logSection, errorInput, waterMark)
}

// parseFailureLine attempts to extract the fuzz target name and input ID
// from a line of fuzzing output. It uses a predefined regular expression
// to match lines that indicate a failure, capturing the relevant details
// if the line conforms to the expected format.
func parseFailureLine(line string) (string, string) {
	// Apply the regular expression to the line to find matches
	matches := fuzzFailureRegex.FindStringSubmatch(line)

	// Return empty strings if no match is found
	if matches == nil {
		return "", ""
	}

	var target, id string
	// Iterate over the named subexpressions to assign values of fuzz target
	// and id.
	for i, name := range fuzzFailureRegex.SubexpNames() {
		switch name {
		case "target":
			target = matches[i]
		case "id":
			id = matches[i]
		}
	}
	return target, id
}

// readFailingInput attempts to read the failing input file from the corpus
// directory.Returns the file contents or a placeholder string if reading fails.
func (fp *fuzzOutputProcessor) readFailingInput(target, id string) string {
	// Construct the path to the failing input file.
	failingInputPath := filepath.Join(target, id)
	inputPath := filepath.Join(fp.corpusDir, failingInputPath)

	// Attempt to read the file contents.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		// If reading fails, return a placeholder string indicating the
		// failure.
		return fmt.Sprintf("\n## Failing testcase (%s)\nFailed to "+
			"read %s: %v", target, failingInputPath, err)
	}

	// If reading succeeds, format the content with a header indicating it's
	// a failing test case.
	return fmt.Sprintf("\n## Failing testcase (%s)\n~~~sh\n%s~~~", target,
		data)
}
