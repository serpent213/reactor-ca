# ReactorCA

ReactorCA is a Python CLI tool to manage a homelab Certificate Authority.

## Overview

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts with DNS and IP alternative names
- Strong key encryption with password protection
- Certificate inventory tracking
- Git integration for tracking changes
- Simple deployment to target locations

## Technical Details

- Python script with main entry point called `ca`
- Modern Python 3.12+ and X.509 best practices
- Python environment provided by Nix DevEnv which uses Poetry for dependency management
- Key dependencies:
  - click: CLI interface
  - cryptography: X.509 operations
  - pyyaml: Configuration management
  - rich: Terminal formatting
  - gitpython: Git operations

## Usage

```bash
# Initialize the CA
poetry run ca init

# Generate a certificate for a host
poetry run ca generate <hostname>

# Renew a specific certificate
poetry run ca renew <hostname>

# List all certificates with their expiration dates
poetry run ca list

# Change password for all encrypted private keys
poetry run ca passwd

# Commit changes to git
poetry run ca commit
```

## Development

```bash
# Run tests
poetry run pytest

# Run linting
poetry run ruff check .
```