#  ______                                    ______
# (_____ \                  _               / _____)  /\
#  _____) ) ____ ____  ____| |_  ___   ____| /       /  \
# (_____ ( / _  ) _  |/ ___)  _)/ _ \ / ___) |      / /\ \
#       | ( (/ ( ( | ( (___| |_| |_| | |   | \_____| |__| |
#       |_|\____)_||_|\____)\___)___/|_|    \______)______|

version := "0.3.0"
dirs := "./cmd ./internal ./test"
packages := "./cmd/... ./internal/..."

help:
    @just --list

build mode="debug":
    #!/usr/bin/env bash
    if [[ "{{mode}}" =~ ^r ]]; then # release
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

    if [ "{{platform}}" = "all" ] || [ "{{platform}}" = "freebsd" ]; then
        echo "Building for FreeBSD x86_64..."
        GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-freebsd-amd64 ./cmd/ca
        echo "Building for FreeBSD ARM64..."
        GOOS=freebsd GOARCH=arm64 go build -ldflags="-s -w -X main.version={{version}}" -o dist/reactor-ca-freebsd-arm64 ./cmd/ca
    fi

build-nix:
    nix build

debug: (build "debug")

release: (build "release")

fmt:
    gofmt -s -w {{dirs}}
    go tool yamlfmt -quiet example_config/ .github/
    nixfmt *.nix

fmt-check:
    @echo "Checking Go formatting..."
    @if [ -n "$(gofmt -s -l {{dirs}})" ]; then \
        echo "Code is not formatted. Run 'just fmt' to fix."; \
        gofmt -s -l {{dirs}}; \
        exit 1; \
    fi
    @echo "Checking YAML formatting..."
    @if ! go tool yamlfmt -lint -quiet example_config/ .github/; then \
        echo "YAML files are not formatted. Run 'just fmt' to fix."; \
        exit 1; \
    fi

vet:
    go vet {{packages}}

staticcheck:
    go tool staticcheck {{packages}}

lint: fmt-check vet staticcheck

test type="all":
    #!/usr/bin/env bash
    if [[ "{{type}}" =~ ^u ]]; then # unit
        go test -v ./cmd/... ./internal/...
    elif [[ "{{type}}" =~ ^i ]]; then # integration
        go test -v -tags integration ./test/integration/...
    elif [[ "{{type}}" =~ ^e ]]; then # e2e
        go test -v -tags e2e ./test/e2e/...
    elif [[ "{{type}}" =~ ^a ]]; then # all
        echo "Running unit tests..."
        go test -v ./cmd/... ./internal/...
        echo "Running integration tests..."
        go test -v -tags integration ./test/integration/...
        echo "Running e2e tests..."
        go test -v -tags e2e ./test/e2e/...
    else
        echo "Invalid test type: {{type}}. Use 'unit', 'integration', 'e2e', or 'all'."
        exit 1
    fi

tidy:
    go mod tidy

update:
    go get -u ./...
    go mod tidy

check: lint build tidy test build-nix

ci: lint tidy test release
