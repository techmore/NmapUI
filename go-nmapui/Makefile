.PHONY: help build run test clean dev build-all install deps

# Variables
APP_NAME=nmapui
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Platforms
PLATFORMS=darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

deps: ## Install dependencies
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

build: ## Build for current platform
	@echo "Building $(APP_NAME) v$(VERSION)..."
	go build $(LDFLAGS) -o bin/$(APP_NAME) cmd/nmapui/main.go
	@echo "✓ Built: bin/$(APP_NAME)"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		OS=$${platform%/*}; \
		ARCH=$${platform#*/}; \
		OUTPUT=dist/$(APP_NAME)-$$OS-$$ARCH; \
		if [ $$OS = "windows" ]; then OUTPUT=$$OUTPUT.exe; fi; \
		echo "Building $$OUTPUT..."; \
		GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $$OUTPUT cmd/nmapui/main.go; \
	done
	@echo "✓ Built all platforms in dist/"

run: ## Run application
	@echo "Starting $(APP_NAME)..."
	go run cmd/nmapui/main.go

dev: ## Run with live reload (requires air)
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

test: ## Run tests
	@echo "Running tests..."
	go test -v -cover ./...

test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	go test -v -race ./...

test-coverage: ## Generate coverage report
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

test-bench: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

bench: ## Run benchmarks (alias for test-bench)
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

lint: ## Run linters
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/ dist/ coverage.out coverage.html
	go clean

install: build ## Install binary to /usr/local/bin
	@echo "Installing $(APP_NAME) to /usr/local/bin..."
	sudo cp bin/$(APP_NAME) /usr/local/bin/
	@echo "✓ Installed: /usr/local/bin/$(APP_NAME)"

# Docker is prohibited in hospital environments
# All deployment must use native binaries

migrate: ## Run database migrations
	@echo "Running migrations..."
	go run cmd/nmapui/main.go migrate

seed: ## Seed database with test data
	@echo "Seeding database..."
	go run cmd/nmapui/main.go seed

release: build-all ## Create release artifacts
	@echo "Creating release artifacts..."
	@mkdir -p dist
	@cd dist && for file in *; do \
		if [ -f "$$file" ]; then \
			tar czf "$$file.tar.gz" "$$file"; \
			shasum -a 256 "$$file.tar.gz" > "$$file.tar.gz.sha256"; \
		fi; \
	done
	@echo "✓ Release artifacts created in dist/"

tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "✓ Tools installed"

mod-update: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

security: ## Run security checks
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec ./...

.DEFAULT_GOAL := help
