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
    set -e

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

check: lint build tidy test build-nix

ci: lint tidy test release

tidy:
    go mod tidy

update:
    go get -u ./...
    go mod tidy
    @just update-flake

update-flake:
    #!/usr/bin/env bash
    echo "Updating vendor hash in flake.nix..."

    # First, set vendorHash to lib.fakeHash
    sed -i.bak 's/vendorHash = ".*";/vendorHash = pkgs.lib.fakeHash;/' flake.nix

    # Try to build and capture the output
    if output=$(nix build .#reactor-ca 2>&1); then
        echo "Build succeeded unexpectedly. No hash update needed."
        # Restore original if build succeeded
        mv flake.nix.bak flake.nix
    else
        # Extract the correct hash from the error output (the "got:" line)
        correct_hash=$(echo "$output" | grep "got:" | grep -o 'sha256-[A-Za-z0-9+/]\{43\}=')
        if [ -n "$correct_hash" ]; then
            echo "Found correct hash: $correct_hash"
            # Update flake.nix with the correct hash
            sed -i "s|vendorHash = pkgs.lib.fakeHash;|vendorHash = \"$correct_hash\";|" flake.nix
            echo "Updated vendorHash in flake.nix"
            rm -f flake.nix.bak

            # Verify the build works now
            echo "Verifying build with new hash..."
            if nix build .#reactor-ca; then
                echo "Build successful with updated vendor hash"
            else
                echo "Build still failing after hash update"
                exit 1
            fi
        else
            echo "Could not extract vendor hash from build output"
            echo "Build output:"
            echo "$output"
            # Restore original on failure
            mv flake.nix.bak flake.nix
            exit 1
        fi
    fi
