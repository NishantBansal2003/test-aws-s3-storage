#!/bin/bash
set -uo pipefail # Enable strict error handling
set -x           # Enable command tracing
shopt -s nullglob

# =============================================================================
# CONFIGURATION
# =============================================================================
# Environment variables for fuzzing process configuration
export PROJECT_SRC_PATH="https://github.com/NishantBansal2003/go-fuzzing-example.git"
export S3_BUCKET_NAME="test-fuzz-bucket"
export CORPUS_DIR_PATH="$HOME/corpus"
export SYNC_FREQUENCY="15m"
export MAKE_TIMEOUT="20m"
export FUZZ_PKGS_PATH="parser,stringutils"
export FUZZ_RESULTS_PATH="$HOME/fuzz_results"
export NUM_WORKERS=3

# Temporary Variables
readonly PROJECT_BRANCH="fuzz-example"
readonly PROJECT_DIR="$HOME/project"

# Fuzz target definitions (package:function)
readonly FUZZ_TARGETS=(
  "parser:FuzzParseComplex"
  "parser:FuzzEvalExpr"
  "stringutils:FuzzUnSafeReverseString"
  "stringutils:FuzzReverseString"
)

# =============================================================================
# FUNCTION DEFINITIONS
# =============================================================================

# Counts the number of test inputs in a corpus directory
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Number of input files
count_corpus_inputs() {
  local pkg="$1"
  local func="$2"

  local dir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz/${func}"

  if [[ -d "$dir" ]]; then
    local num_inputs
    num_inputs=$(ls "$dir" | wc -l | xargs)
    echo $num_inputs
  else
    echo 0
  fi
}

# Measures the code coverage for a fuzz target
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Coverage percentage value
measure_fuzz_coverage() {
  local pkg="$1"
  local func="$2"
  local coverage_result

  pushd "${PROJECT_DIR}/${pkg}" >/dev/null

  # Enable Go fuzzing debug output
  export GODEBUG="fuzzdebug=1"

  # Count existing corpus inputs
  local num_inputs
  num_inputs=$(count_corpus_inputs "$pkg" "$func")

  # Incrementing to account for the seed corpus entry; otherwise, we won't get any coverage bits.
  ((num_inputs++))

  # Run coverage measurement
  coverage_result=$(go test -run="^${func}$" -fuzz="^${func}$" \
    -fuzztime="${num_inputs}x" \
    -test.fuzzcachedir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz" |
    grep "initial coverage bits:" | grep -oE "[0-9]+$" || echo 0)

  popd >/dev/null

  echo "$coverage_result"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Clone the target repository
echo "🚀 Cloning project repository..."
git clone --branch "$PROJECT_BRANCH" --single-branch --depth 1 \
  "$PROJECT_SRC_PATH" "$PROJECT_DIR"

# Initialize data stores
declare -A initial_input_counts
declare -A initial_coverage_metrics
declare -A final_input_counts
declare -A final_coverage_metrics

# Capture initial corpus state
echo "📊 Recording initial corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"$target"
  echo "  - $pkg/$func"
  initial_input_counts["$target"]=$(count_corpus_inputs "$pkg" "$func")
  initial_coverage_metrics["$target"]=$(measure_fuzz_coverage "$pkg" "$func")
done

# Execute fuzzing process
echo "🔍 Starting fuzzing process (timeout: $MAKE_TIMEOUT)..."
mkdir -p "$FUZZ_RESULTS_PATH"
MAKE_LOG="$FUZZ_RESULTS_PATH/make_run.log"

# Run `make run` under `timeout`, capturing stdout+stderr into MAKE_LOG.
timeout -s INT --preserve-status "$MAKE_TIMEOUT" make run 2>&1 | tee "$MAKE_LOG"
status=${PIPESTATUS[0]}

# Handle exit codes:
#   130 → timeout sent SIGINT; treat as expected termination
#   any other non-zero → unexpected error
if [[ $status -ne 130 ]]; then
  echo "❌ Fuzzing exited with unexpected error (status: $status)."
  exit "$status"
fi

# List of required patterns to check in the log
readonly REQUIRED_PATTERNS=(
  'Downloaded object'
  'Successfully extracted zip archive.'
  'msg="Per-target fuzz timeout calculated" duration=11m15s'
  'workerID=1'
  'workerID=2'
  'workerID=3'
  'No permission to create a GitHub issue; logging instead.'
  'msg="Known crash detected. Please fix the failing testcase." target=FuzzParseComplex package=parser log_file=parser_FuzzParseComplex_342a5c470d17be27_failure.md'
  'msg="Known crash detected. Please fix the failing testcase." target=FuzzUnSafeReverseString package=stringutils log_file=stringutils_FuzzUnSafeReverseString_0345b61f9a8eecc9_failure.md'
  'Successfully zipped and uploaded corpus'
)

# Verify that worker logs contain expected entries
echo "🔍 Verifying worker log entries in $MAKE_LOG..."
for pattern in "${REQUIRED_PATTERNS[@]}"; do
  if ! grep -q -- "$pattern" "$MAKE_LOG"; then
    echo "❌ ERROR: Missing expected log entry: $pattern"
    exit 1
  fi
done

# Download corpus.zip from LocalStack S3
aws --endpoint-url=http://localhost:4566 s3 cp s3://test-fuzz-bucket/corpus.zip "$HOME/corpus.zip"

# Unzip corpus.zip into $HOME/corpus
unzip -o "$HOME/corpus.zip" -d "$HOME/corpus"

# Capture final corpus state
echo "📈 Recording final corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"$target"
  echo "  - $pkg/$func"
  final_input_counts["$target"]=$(count_corpus_inputs "$pkg" "$func")
  final_coverage_metrics["$target"]=$(measure_fuzz_coverage "$pkg" "$func")
done

# Validate corpus growth
echo "🔎 Validating corpus growth..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_count=${initial_input_counts["$target"]}
  final_count=${final_input_counts["$target"]}

  if [[ $final_count -lt $initial_count ]]; then
    echo "❌ ERROR: $target regressed - inputs decreased from $initial_count to $final_count"
    exit 1
  fi
done

# Validate coverage metrics
echo "✅ Validating coverage metrics..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_cov=${initial_coverage_metrics["$target"]}
  final_cov=${final_coverage_metrics["$target"]}

  if [[ $final_cov -lt $initial_cov ]]; then
    echo "❌ ERROR: $target coverage decreased from $initial_cov to $final_cov"
    exit 1
  fi
done

# Verify crash reports
echo "📄 Checking crash reports..."
required_crashes=(
  "$FUZZ_RESULTS_PATH/parser_FuzzParseComplex_342a5c470d17be27_failure.md"
  "$FUZZ_RESULTS_PATH/stringutils_FuzzUnSafeReverseString_0345b61f9a8eecc9_failure.md"
)

for crash_file in "${required_crashes[@]}"; do
  if [[ ! -f "$crash_file" ]]; then
    echo "❌ ERROR: Missing crash report: $crash_file"
    exit 1
  fi

  if ! grep -q "go test fuzz v1" "$crash_file"; then
    echo "❌ ERROR: Invalid crash report format in $crash_file"
    exit 1
  fi
done

# Cleanup resources
echo "🧹 Cleaning up resources..."
rm -rf "$PROJECT_DIR"
rm -rf "$FUZZ_RESULTS_PATH"

echo "🎉 All validations completed successfully!"
exit 0
