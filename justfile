###################################
# ReactorCA
# by Steffen Beyer in 2025
###################################

version := "0.3.0"
dirs := "./cmd ./internal"
packages := "./cmd/... ./internal/..."

help:
    @just --list

build mode="debug":
    #!/usr/bin/env bash
    if [ "{{mode}}" = "release" ]; then
        go build -ldflags="-s -w -X main.version={{version}}" -v ./cmd/ca
    else
        go build -ldflags="-X main.version={{version}}-debug" -v ./cmd/ca
    fi

build-cross platform="all":
    #!/usr/bin/env bash
    mkdir -p dist

    if [ "{{platform}}" = "all" ] || [ "{{platform}}" = "linux" ]; then
        echo "Building for Linux x86_64..."
        GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-linux-amd64 ./cmd/ca
        echo "Building for Linux ARM64..."
        GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-linux-arm64 ./cmd/ca
    fi

    if [ "{{platform}}" = "all" ] || [ "{{platform}}" = "darwin" ]; then
        echo "Building for macOS x86_64..."
        GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-darwin-amd64 ./cmd/ca
        echo "Building for macOS ARM64..."
        GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-darwin-arm64 ./cmd/ca
    fi

    if [ "{{platform}}" = "all" ] || [ "{{platform}}" = "windows" ]; then
        echo "Building for Windows x86_64..."
        GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-windows-amd64.exe ./cmd/ca
        echo "Building for Windows ARM64..."
        GOOS=windows GOARCH=arm64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-windows-arm64.exe ./cmd/ca
    fi

debug: (build "debug")

release: (build "release")

fmt:
    gofmt -s -w {{dirs}}
    yamlfmt -quiet example_config/ .github/

fmt-check:
    @echo "Checking Go formatting..."
    @if [ -n "$(gofmt -s -l {{dirs}})" ]; then \
        echo "Code is not formatted. Run 'just fmt' to fix."; \
        gofmt -s -l {{dirs}}; \
        exit 1; \
    fi
    @echo "Checking YAML formatting..."
    @if ! yamlfmt -lint -quiet example_config/ .github/; then \
        echo "YAML files are not formatted. Run 'just fmt' to fix."; \
        exit 1; \
    fi

vet:
    go vet {{packages}}

staticcheck:
    staticcheck {{packages}}

lint: fmt-check vet staticcheck

test-unit:
    go test -v ./...

test-integration:
    go test -v -tags integration ./...

test: test-unit test-integration

tidy:
    go mod tidy

update:
    go get -u ./...
    go mod tidy

check: lint build test tidy

ci: lint tidy test release

release-all: build-cross
