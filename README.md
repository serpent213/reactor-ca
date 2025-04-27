# ReactorCA

A Python CLI tool to manage a homelab Certificate Authority.

## Features

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts
- Support for DNS and IP alternative names
- Strong key encryption with password protection
- Certificate inventory tracking
- Git integration for tracking changes
- Simple deployment to target locations

## Getting Started

### Installation

ReactorCA uses Poetry for dependency management. To install:

```bash
# If in the Nix DevEnv, this is already set up
poetry install
```

### Initialize

First, create the default config files:

```bash
poetry run ca init
```

This will create default configuration files in the `config/` directory. Edit them according to your needs.

### Generate CA Certificate

After editing the configuration, initialize the CA:

```bash
poetry run ca init
```

This will create a self-signed CA certificate and private key (encrypted with the password you provide).

### Generate Host Certificate

To generate a certificate for a host defined in your hosts.yaml:

```bash
poetry run ca generate hostname
```

### List Certificates

To list all certificates with their expiration dates:

```bash
poetry run ca list
```

### Renew Certificates

To renew a specific certificate:

```bash
poetry run ca renew hostname
```

Or to renew all certificates:

```bash
poetry run ca renew-all
```

### Change Password

To change the password for all encrypted private keys:

```bash
poetry run ca passwd
```

### Commit Changes to Git

To stage and commit all changes:

```bash
poetry run ca commit
```

## Configuration

### CA Configuration

The CA configuration is stored in `config/ca_config.yaml`:

```yaml
ca:
  common_name: "Reactor CA"
  organization: "Reactor Homelab"
  organization_unit: "IT"
  country: "DE"
  state: "Berlin"
  locality: "Berlin"
  email: "admin@example.com"
  key:
    algorithm: "RSA"  # or "EC"
    size: 4096        # or curve name for EC
  validity_days: 3650   # 10 years
  password:
    min_length: 12
    storage: "session"  # "none", "session", "keyring"
```

### Hosts Configuration

Host certificates are configured in `config/hosts.yaml`:

```yaml
hosts:
  - name: "server1.example.com"
    common_name: "server1.example.com"
    alternative_names:
      dns:
        - "www.example.com"
        - "api.example.com"
      ip:
        - "192.168.1.10"
    destination: "../path/to/deploy/cert/server1.pem"
    validity_days: 365
    key:
      algorithm: "RSA"
      size: 2048
```

## Development

### Testing

```bash
poetry run pytest
```

### Linting

```bash
poetry run ruff check .
```

## License

This project is open source under the MIT license.