# ReactorCA

ReactorCA is a Python CLI tool to manage a homelab Certificate Authority.

## Development Commands

**IMPORTANT: Use these commands for development tasks:**

```bash
# Format code
# USE `fix` INSTEAD!
# poetry run poe format

# Run linting
# USE `fix` INSTEAD!
# poetry run poe lint

# Run type checking
poetry run poe typecheck

# Run tests
poetry run poe test

# Run all checks and tests
poetry run poe check

# Fix format and lint (unsafe)
poetry run poe fix
```

Use `rg` instead of `grep` for code searching.

Remember to run `poetry install` after modifying dependencies.

## Overview

- Create and manage a self-signed Certificate Authority
- Generate, renew, and rekey certificates for hosts
- Support for DNS and IP alternative names
- Strong key encryption with password protection
- Certificate inventory tracking
- Certificate chain support for services requiring full chain
- Export unencrypted private keys when needed
- Flexible password options (prompt, environment variable, file)
- Run deployment commands after certificate exports
- No backup functionality, we expect to keep the cert store in a Git repo
- Do not take care of backward compatibility when making changes

Directory structure:

- `reactor_ca`: main source code folder
- `reactor_ca/schemas`: YAML schemas
- `tests`: Pytest tests
- `example_config`: Some "full blown" config examples for users to look at

## Organization Principles

- `config.py`: Configuration management and validation
- `store.py`: File operations, storage management, and inventory
- `crypto.py`: Cryptographic operations for certificate generation and validation
- `ca_operations.py`: High-level CA management operations
- `host_operations.py`: Host certificate operations
- `utils.py`: General utilities (mainly console/CLI/UI)

## Technical Details

- Python script with main entry point called `ca`
- Modern Python 3.12+ and X.509 best practices
- Keep all imports at top of file, order does not matter
- Python environment provided by Nix DevEnv which uses Poetry for dependency management
- YAML configuration validation using Yamale schemas
- Key dependencies:
  - click: CLI interface
  - cryptography: X.509 operations
  - pyyaml: Configuration management
  - yamale: Schema validation
  - rich: Terminal formatting and output

## Typing Guidelines

To pass linting checks, follow these rules:

1. **Type Annotations**:
   - Always include type annotation for `self` in class methods: `def method(self: ClassName) -> ReturnType:`
   - Use Python 3.10+ union syntax: `X | Y` instead of `Union[X, Y]` 
   - Always include return type annotations for functions

2. **Type Patterns**:
   - Use specific types from cryptography module when applicable:
     - `PrivateKeyTypes` and `PublicKeyTypes` for keys
     - Use proper return type signatures: `tuple[bool, x509.Certificate | None, SubjectIdentity]`
   - For collections, use concrete types: `dict[str, Any]`, `list[str]`, etc.

## String Delimiters

- Prefer double quotes (`"`) for string delimiters in general
- Use single quotes (`'`) for strings that contain double quotes inside them to avoid unnecessary escaping
- For docstrings, always use triple double quotes (`"""`)
- Be consistent within the same file


## Command Structure

```
ca
├── config         # Configuration management
│   ├── init       # Generate initial config files
│   └── validate   # Validate config files
├── ca             # CA management
│   ├── issue      # Create/renew a CA
│   ├── import     # Import existing CA (cert+key)
│   ├── renew      # Renew the CA certificate
│   ├── rekey      # Generate new key and renew CA certificate
│   └── info       # Show CA info
├── host           # Host certificate operations
│   ├── issue      # Create/renew certificates
│   ├── import-key # Import existing key
│   ├── export-key # Export unencrypted private key
│   ├── rekey      # Generate new key and issue certificate
│   ├── list       # List all certificates
│   ├── clean      # Remove unconfigured hosts
│   ├── deploy     # Deploy certificates
│   └── sign-csr   # Sign CSR (standalone operation)
└── util           # Utility operations
    └── passwd     # Change encryption password
```

Make sure to update the README.md (only in the root folder!) and `example_config` to match source code changes.
