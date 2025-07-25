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
  - `internal/infra/identity/` - Identity provider implementations (password, SSH, age plugins)
- `internal/ui/` - Console output formatting and user interaction

Key architectural principles:
- **Stateless operations**: Each command execution is independent
- **Configuration-driven**: All settings defined in YAML files (`config/ca.yaml`, `config/hosts.yaml`)
- **Secure storage**: Private keys encrypted using age-based encryption with configurable identity providers
- **Clean interfaces**: Domain interfaces implemented by infrastructure layer

## Tree-Sitter Integration

Initialize tree-sitter for code exploration:
```bash
# Configure and register the project
mcp__tree-sitter__configure --config-path .tree-sitter-mcp-config.yaml
mcp__tree-sitter__register_project_tool --path /Users/self/Documents/projects/ReactorCA --name ReactorCA --description "Go-based CLI tool for managing a private PKI"
```

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

# CA Management
./ca ca create                  # Create new CA
./ca ca renew                   # Renew CA certificate
./ca ca rekey                   # Regenerate CA private key
./ca ca info                    # Show CA information
./ca ca import                  # Import external CA
./ca ca reencrypt               # Change master password

# Host Certificate Management
./ca host issue web-server      # Issue new certificate
./ca host deploy web-server     # Deploy certificate
./ca host export-key web-server # Export private key
./ca host import-key web-server # Import private key
./ca host sign-csr              # Sign external CSR
./ca host list                  # List all certificates
./ca host clean                 # Remove orphaned certificates

# Configuration
./ca config validate            # Validate configuration files

# Use custom root directory
./ca --root /path/to/pki ca create
```

## Key Components

### Application Layer (`internal/app/application.go`)
Central orchestrator that coordinates between domain interfaces. Key methods:
- `CreateCA()` - Generate new CA key/cert
- `RenewCA()` - Renew CA certificate keeping same key
- `RekeyCA()` - Generate new CA key and certificate
- `InfoCA()` - Display CA certificate information
- `ImportCA()` - Import external CA certificate and key
- `IssueHost()` - Create/renew host certificates
- `DeployHost()` - Execute deployment commands with variable substitution
- `ExportHostKey()` - Export host private key
- `ImportHostKey()` - Import host private key
- `SignCSR()` - Sign external certificate signing request
- `ReencryptKeys()` - Re-encrypt all keys with new identity provider
- `ValidateConfig()` - Validate configuration files

### Domain Interfaces (`internal/domain/interfaces.go`)
- `CryptoService` - All cryptographic operations
- `CryptoServiceFactory` - Factory for creating crypto services
- `Store` - Certificate/key persistence 
- `ConfigLoader` - YAML configuration loading
- `IdentityProvider` - Age identity management for encryption/decryption
- `IdentityProviderFactory` - Factory for creating identity providers
- `Commander` - External command execution
- `ValidationService` - Round-trip validation of crypto operations

### Configuration Types (`internal/domain/config.go`)
- `CAConfig` - Root CA settings with encryption configuration
- `HostsConfig` - Host certificate definitions
- `HostConfig` - Individual host certificate config
- `EncryptionConfig` - Identity provider configuration
- `SSHConfig` - SSH key-based encryption settings
- `PluginConfig` - Age plugin configuration
- `HostInfo` - DTO with certificate status and algorithm details
- `HostStatus` - Enumeration (issued, configured, orphaned)

## Store Structure
```
store/
├── ca/
│   ├── ca.crt           # CA certificate (PEM)
│   └── ca.key.age       # Age-encrypted CA private key
├── hosts/
│   └── <host-id>/
│       ├── cert.crt     # Host certificate (PEM) 
│       └── cert.key.age # Age-encrypted host private key
└── ca.log               # Operation log
```

## Security Notes

- All private keys encrypted using age-based encryption with ChaCha20-Poly1305
- Supports multiple identity providers:
  - **Password-based**: Derived using scrypt for key derivation
  - **SSH keys**: Use existing SSH private keys as age identities
  - **Age plugins**: Hardware tokens (YubiKey, TPM, Apple Secure Enclave)
- Identity provider explicitly configured via `encryption.provider` field in config
- Temporary files (for deployment) use 0600 permissions and are cleaned up

## Identity Providers

ReactorCA supports three encryption methods for private key protection:

### Password-Based Encryption (`password`)
- Uses scrypt-derived keys with age encryption
- Password sources: configured file path → configured env var (default: `REACTOR_CA_PASSWORD`) → interactive prompt
- Default and most portable option

### SSH Key-Based Encryption (`ssh`)
- Leverages existing SSH private keys as age identities
- Automatically converts SSH keys to age format
- Supports RSA, Ed25519, and ECDSA keys
- Configure via `encryption.ssh.key_path` in config

### Age Plugin-Based Encryption (`plugin`)
- Hardware security modules and external providers
- Supported plugins:
  - **YubiKey PIV**: `age-plugin-yubikey` for PIV smartcard slots
  - **Apple Secure Enclave**: `age-plugin-se` for macOS hardware encryption
  - **TPM**: `age-plugin-tpm` for Trusted Platform Module
- Configure via `encryption.plugin.name` and `encryption.plugin.identity` in config

## Development Environment

This project uses `devenv.nix` for reproducible development environments. The environment provides:
- Go toolchain
- OpenSSL for cryptographic operations

Run `devenv shell` to enter the development environment.

## Console Output

All console output should be handled through the `internal/ui/` package for consistency and proper styling. The UI package provides:
- `ui.Success()` - Green checkmark for success messages
- `ui.Error()` - Red X for error messages to stderr
- `ui.Warning()` - Yellow exclamation for warnings
- `ui.Info()` - Cyan info symbol for general information
- `ui.Action()` - Cyan arrow for progress/action messages
- `ui.PrintBlock()` - For pre-formatted text blocks
- Color formatting functions and table utilities

Never use `fmt.Printf` or `log.Printf` directly in command handlers - route all output through the UI package.

## Testing Strategy

The codebase is structured for testability with interfaces mocking infrastructure dependencies. Test structure:

```
test/
├── integration/    # Integration tests with real filesystem
└── e2e/            # End-to-end CLI tests

# Unit tests are co-located with source files (*_test.go)
```

Focus testing on:
- Application layer business logic
- Cryptographic operations validation (including age encryption)
- Identity provider implementations
- Configuration parsing edge cases
- Store operations with filesystem mocks
- CLI command integration and end-to-end flows

### Test Commands
```bash
just test             # All tests
just test-unit        # Unit tests only
just test-integration # Integration tests with filesystem
just test-e2e         # End-to-end CLI tests
```
