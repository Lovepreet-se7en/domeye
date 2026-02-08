# DOMEye Makefile

.PHONY: build install test clean run

# Build the binary
build:
	@echo "Building DOMEye..."
	@go build -o domeye .
	@echo "Build complete: domeye"

# Install to GOPATH
install:
	@echo "Installing DOMEye..."
	@go install .
	@echo "Installation complete"

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f domeye
	@rm -rf scan_report.html
	@echo "Clean complete"

# Quick run
run:
	@echo "Building and running..."
	@go build -o domeye .
	@./domeye scan --help
