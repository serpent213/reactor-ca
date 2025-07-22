dirs := "./cmd ./internal"
packages := "./cmd/... ./internal/..."

help:
    @just --list

build mode="debug":
    #!/usr/bin/env bash
    if [ "{{mode}}" = "release" ]; then
        go build -ldflags="-s -w" -v ./cmd/ca
    else
        go build -v ./cmd/ca
    fi

debug: (build "debug")

release: (build "release")

fmt:
    gofmt -s -w {{dirs}}

fmt-check:
    @if [ -n "$(gofmt -s -l {{dirs}})" ]; then \
        echo "Code is not formatted. Run 'just fmt' to fix."; \
        gofmt -s -l {{dirs}}; \
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

check: lint build test tidy

ci: lint tidy test release
