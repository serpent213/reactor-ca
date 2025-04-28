# ReactorCA

ReactorCA is a Python CLI tool to manage a homelab Certificate Authority.

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

Directory structure:

- `reactor_ca`: main source code folder
- `reactor_ca/schemas`: YAML schemas
- `tests`: Pytest tests
- `example_config`: Some "full blown" config examples for users to look at

## Technical Details

- Python script with main entry point called `ca`
- Modern Python 3.12+ and X.509 best practices
- Python environment provided by Nix DevEnv which uses Poetry for dependency management
- YAML configuration validation using Yamale schemas
- Key dependencies:
  - click: CLI interface
  - cryptography: X.509 operations
  - pyyaml: Configuration management
  - yamale: Schema validation
  - rich: Terminal formatting and output

## Command Structure

```
ca
├── config         # Configuration management
│   ├── init       # Generate initial config files
│   └── validate   # Validate config files
├── ca             # CA management
│   ├── create     # Create a new CA
│   ├── import     # Import existing CA (cert+key)
│   ├── renew      # Renew the CA certificate
│   ├── rekey      # Generate new key and renew CA certificate
│   └── info       # Show CA info
├── host           # Host certificate operations
│   ├── issue      # Issue/renew certificates
│   ├── import     # Import existing key
│   ├── export-key # Export unencrypted private key
│   ├── rekey      # Generate new key and issue certificate
│   ├── list       # List all certificates
│   ├── deploy     # Deploy certificates
│   └── sign-csr   # Sign CSR (standalone operation)
└── util           # Utility operations
    └── passwd     # Change encryption password
```

## Development

```bash
# Run tests
poetry run pytest

# Run linting
poetry run ruff check .
```

Use `rg` instead of `grep`.

Make sure to update the README.md and `example_config` to match source code changes.
