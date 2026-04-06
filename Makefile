.PHONY: build test lint clean install

# Build the binary
build:
	go build -o ak-47 ./cmd/cli

# Run tests
test:
	go test -v ./...

# Run linter
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -f ak-47

# Install dependencies
install:
	go mod download
	go get -d ./...

# Run the application
run: build
	./ak-47
