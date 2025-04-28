# ReactorCA

A Python CLI tool to manage a homelab Certificate Authority.

## Features

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts
- Support for DNS and IP alternative names
- Strong key encryption with password protection
- Certificate inventory tracking
- Simple deployment to target locations
- Certificate chain support (CA + host certificate)
- Flexible password options (prompt, environment variable, file)
- Export unencrypted private keys when needed
- Run deployment scripts after certificate exports

## Getting Started

### Installation

ReactorCA uses Poetry for dependency management. To install:

```bash
# If in the Nix DevEnv, this is already set up
poetry install
```

### Initialize Configuration

First, create the default config files:

```bash
poetry run ca config init
```

This will create default configuration files in the `config/` directory. Edit them according to your needs.

> **Note**: The `config` directory is excluded from version control. Example configurations can be found in the `example_config` directory for reference.

### Create CA Certificate

After editing the configuration, create the CA:

```bash
poetry run ca ca create
```

This will create a self-signed CA certificate and private key (encrypted with the password you provide).

### Issue Host Certificate

To issue a certificate for a host defined in your hosts.yaml:

```bash
poetry run ca host issue hostname
```

### List Certificates

To list all certificates with their expiration dates:

```bash
poetry run ca host list
```

### Renew Certificates

To renew a specific certificate:

```bash
poetry run ca host issue hostname
```

Or to renew all certificates:

```bash
poetry run ca host issue --all
```

### Change Password

To change the password for all encrypted private keys:

```bash
poetry run ca util passwd
```

## Common Workflows

### New CA Workflow

```bash
# Initialize configuration
poetry run ca config init

# Edit configuration
vim config/ca_config.yaml

# Create the CA
poetry run ca ca create

# Create host config
vim config/hosts.yaml

# Issue certificates
poetry run ca host issue server1.example.com
```

### Import CA Workflow

```bash
# Initialize configuration (optional)
poetry run ca config init

# Import existing CA
poetry run ca ca import --cert path/to/ca.crt --key path/to/ca.key

# Create host config
vim config/hosts.yaml

# Issue certificates
poetry run ca host issue server1.example.com
```

### Import Host Keys Workflow

```bash
# Import existing key
poetry run ca host import server1.example.com --key path/to/key.pem

# Finalize host config
vim config/hosts.yaml

# Issue certificate using imported key
poetry run ca host issue server1.example.com
```

### Key Rotation Workflow

```bash
# Rotate the CA key and certificate
poetry run ca ca rekey

# Rotate a specific host key and certificate
poetry run ca host rekey server1.example.com

# Rotate all host keys and certificates
poetry run ca host rekey --all
```

### Deploy Certificates

```bash
# Deploy a specific certificate
poetry run ca host deploy server1.example.com

# Deploy all certificates
poetry run ca host deploy --all

# Issue and deploy in one step
poetry run ca host issue server1.example.com --deploy
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
  validity:
    years: 10         # Can specify years or days
    # days: 3650      # Alternative: specify in days
  password:
    min_length: 12
    # Password is cached in memory for the duration of the program execution
    file: ""          # Path to password file (optional)
    env_var: "REACTOR_CA_PASSWORD"  # Environment variable for password (optional)
```

See the `example_config` directory for reference examples.

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
    export:
      cert: "/path/to/export/cert/server1.pem"
      chain: "/path/to/export/cert/server1-chain.pem"  # Optional full chain
    deploy:
      command: "systemctl reload nginx"  # Optional deployment command
    validity:
      years: 1           # Can specify years or days
      # days: 365        # Alternative: specify in days
    key:
      algorithm: "RSA"
      size: 2048
```

## Password Management Options

ReactorCA offers several ways to provide the master password:

1. **Interactive Prompt** (default): The tool will ask for the password when needed
2. **Environment Variable**: Set the `REACTOR_CA_PASSWORD` environment variable
3. **Password File**: Specify a file path in the `ca_config.yaml` file's `password.file` setting

The tool tries these methods in order: file, environment variable, interactive prompt.

## Development

### Testing

```bash
poetry run pytest
```

### Linting

```bash
poetry run ruff check .
```

## Limitations and Future Work

ReactorCA is designed for homelab use and has some limitations:

- No revocation/CRL support (for now)
- No PKCS#12 support (for now)
- No automation for rekeying/key deployment (for now)

## License

This project is open source under the MIT license.