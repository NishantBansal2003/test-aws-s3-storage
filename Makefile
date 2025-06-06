# Variables
APP_NAME := go-continuous-fuzz
DOCKER_APP_NAME := go-continuous-fuzz

#? build: Build the project and create go-continuous-fuzz binary
build:
	@go build -o $(APP_NAME)

#? run: Run the application with command-line flags set in ARGS or ENV variables specified in the process environment
run: build
	@./$(APP_NAME) $(ARGS)

#? run-help: Show this help message
run-help: build
	@./$(APP_NAME) --help

#? docker: Build the docker image of go-continuous-fuzz project
docker:
	@docker build -t $(DOCKER_APP_NAME) .

#? docker-run-file: Run the go-continuous-fuzz container, loading every variable from $(ENV_FILE).
docker-run-file: docker
	@# ensure the file exists
	@if [ ! -f "$(ENV_FILE)" ]; then \
	  echo "Error: '$(ENV_FILE)' not found. Please set the ENV_FILE environment variable."; \
	  exit 1; \
	fi
	@echo "Running $(DOCKER_APP_NAME) with env file '$(ENV_FILE)'"
	docker run --env-file "$(ENV_FILE)" $(VOLUME_MOUNTS) "$(DOCKER_APP_NAME)"

#? docker-run-env: Run the go-continuous-fuzz container with each required env var supplied on the command line or already exported in the shell.
docker-run-env: docker
	@echo "Running $(DOCKER_APP_NAME) with explicit environment variables"
	docker run \
	  --env NUM_WORKERS="$(NUM_WORKERS)" \
	  --env PROJECT_SRC_PATH="$(PROJECT_SRC_PATH)" \
	  --env S3_BUCKET_NAME="$(S3_BUCKET_NAME)" \
	  --env SYNC_FREQUENCY="$(SYNC_FREQUENCY)" \
	  --env FUZZ_PKGS_PATH="$(FUZZ_PKGS_PATH)" \
	  --env FUZZ_RESULTS_PATH="$(FUZZ_RESULTS_PATH)" \
	  $(VOLUME_MOUNTS) \
	  "$(DOCKER_APP_NAME)"

#? test: Run unit and integration tests
test: unit-test e2e-test

#? unit-test: Run unit tests with verbose output
unit-test:
	go test ./... -v

#? e2e-test: Run e2e(integration) tests
e2e-test:
	./scripts/e2e_test.sh

#? cover: Generate the test coverage
cover:
	go test -cover ./...

#? lint: Run golangci-lint
lint:
	golangci-lint run -v

#? fmt: Format the code
fmt:
	go fmt ./...

#? clean: Clean binaries
clean:
	@rm -f $(APP_NAME)

#? all: Run all targets
all: fmt lint test run

#? help: List all available make targets with their descriptions
help: Makefile
	@$(call print, "Listing commands:")
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'