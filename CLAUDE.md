# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ReactorCA is a Go-based CLI tool for managing a private PKI (Public Key Infrastructure) for homelab and small business environments.

## Architecture

The project follows Clean Architecture principles with clear separation of concerns:

- `cmd/ca/` - CLI commands and entry point
- `internal/app/` - Application service layer (business logic orchestration)
- `internal/domain/` - Core domain interfaces, types, and errors
- `internal/infra/` - Infrastructure implementations (crypto, storage, config loading)

Key architectural principles:
- **Stateless operations**: Each command execution is independent
- **Configuration-driven**: All settings defined in YAML files (`config/ca.yaml`, `config/hosts.yaml`)
- **Secure storage**: Private keys encrypted at rest with master password
- **Clean interfaces**: Domain interfaces implemented by infrastructure layer

## Development Commands

This project uses [just](https://github.com/casey/just) for task automation. Run `just help` to see available commands.

### Common Commands
```bash
# Build the binary (debug mode)
just build

# Build optimized release binary
just release

# Format code
just fmt

# Run linting and checks
just lint

# Run tests
just test             # All tests
just test-unit        # Unit tests only
just test-integration # Integration tests only

# Full CI pipeline
just ci

# Complete check (lint, build, test, tidy)
just check
```

### CLI Usage Pattern
```bash
# Initialize a new PKI environment
./ca init

# Create CA
./ca ca create

# Issue host certificate
./ca host issue web-server

# Use custom root directory
./ca --root /path/to/pki ca create
```

## Key Components

### Application Layer (`internal/app/application.go`)
Central orchestrator that coordinates between domain interfaces. Key methods:
- `CreateCA()` - Generate new CA key/cert
- `IssueHost()` - Create/renew host certificates
- `DeployHost()` - Execute deployment commands with variable substitution
- `ChangePassword()` - Re-encrypt all keys with new password

### Domain Interfaces (`internal/domain/interfaces.go`)
- `CryptoService` - All cryptographic operations
- `Store` - Certificate/key persistence 
- `ConfigLoader` - YAML configuration loading
- `PasswordProvider` - Master password management
- `Commander` - External command execution

### Configuration Types (`internal/domain/config.go`)
- `CAConfig` - Root CA settings
- `HostsConfig` - Host certificate definitions
- `HostConfig` - Individual host certificate config

## Store Structure
```
store/
├── ca/
│   ├── ca.crt         # CA certificate (PEM)
│   └── ca.key.enc     # Encrypted CA private key (PKCS#8)
├── hosts/
│   └── <host-id>/
│       ├── cert.crt   # Host certificate (PEM) 
│       └── cert.key.enc # Encrypted host private key
└── ca.log             # Operation log
```

## Security Notes

- All private keys stored encrypted with PKCS#8 + AES-256-CBC
- Master password retrieved from: file → env var → interactive prompt
- Temporary files (for deployment) use 0600 permissions and are cleaned up
- Command execution uses `strings.Fields()` split to prevent shell injection

## Development Environment

This project uses `devenv.nix` for reproducible development environments. The environment provides:
- Go toolchain
- OpenSSL for cryptographic operations

Run `devenv shell` to enter the development environment.

## Testing Strategy

The codebase is structured for testability with interfaces mocking infrastructure dependencies. Focus testing on:
- Application layer business logic
- Cryptographic operations validation
- Configuration parsing edge cases
- Store operations with filesystem mocks
