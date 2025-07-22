# ReactorCA

A Go CLI tool to manage a homelab Certificate Authority.

Typical usage scenario: Run it on your desktop to renew and deploy certificates for your LAN/VPN devices once a year.

## Features

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts
- Strong key encryption with password protection (AES-256-GCM and PBKDF2)
- Certificate inventory and expiration tracking
- Certificate chain support (CA + host certificate)
- Flexible password options (prompt, environment variable, file)
- Export unencrypted private keys when needed
- Simple deployment to target locations via shell scripts
- Run deployment scripts after certificate exports
- Single statically-linked binary with no runtime dependencies

## Motivation and Design Targets

ReactorCA fills a gap in the homelab PKI space by providing:

- **Command-line focused**: Unlike GUI-heavy tools like [XCA](https://www.hohnstaedt.de/xca/), ReactorCA is built for automation and scripting
- **Modern implementation**: Addresses limitations of older tools like [easy-ca](https://github.com/redredgroovy/easy-ca) with updated cryptographic standards
- **Plug & play**: Minimal configuration required to get started
- **Secure by default**: Strong encryption, secure key storage, and safe deployment practices built-in

## Cryptographic Implementation

ReactorCA is built on proven cryptographic foundations:

### Core Libraries
- **Go Standard Crypto**: Uses `crypto/x509` for certificate operations, `crypto/rsa` and `crypto/ecdsa` for key generation (RSA 2048-4096, ECDSA P-256/384/521, Ed25519), and `crypto/rand` for secure randomness
- **PKCS#8 Encryption**: Based on [Yutong Wang's pkcs8 library](https://github.com/youmark/pkcs8) with enhanced AES-GCM support

### Key Protection
Every `.key.enc` file is encrypted using:
- **AES-256-GCM**: Authenticated encryption for private keys
- **PBKDF2**: Strong key derivation with high iteration counts
- **Secure storage**: Password-protected encryption at rest

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/your-org/reactor-ca/releases).

### Build from Source

```bash
git clone https://github.com/your-org/reactor-ca.git
cd reactor-ca
go build -o reactor-ca ./cmd/reactor-ca
```

## Quick Start

### 1. Initialize Configuration

First, create the default config files:

```bash
./reactor-ca init
```

This creates default configuration files in the `config/` directory. Edit them according to your needs.

### 2. Create CA Certificate

After editing the configuration, create the CA:

```bash
./reactor-ca ca create
```

This creates a self-signed CA certificate and private key (encrypted with the password you provide).

### 3. Issue Host Certificate

To issue a certificate for a host defined in your hosts.yaml:

```bash
./reactor-ca host issue web-server-example
```

### 4. List Certificates

To list all certificates with their expiration dates:

```bash
./reactor-ca host list
```

### 5. Deploy Certificate

To run the deployment command for a host:

```bash
./reactor-ca host deploy web-server-example
```

## CLI Reference

### Global Flags

- `--root <path>` - Root directory for config and store (env: `REACTOR_CA_ROOT`)

### CA Management

| Command | Description |
|---------|-------------|
| `reactor-ca ca create` | Create a new CA key and self-signed certificate |
| `reactor-ca ca renew` | Renew the CA certificate using the existing key |
| `reactor-ca ca rekey` | Create a new key and certificate, replacing the old ones |
| `reactor-ca ca info` | Display detailed information about the CA certificate |
| `reactor-ca ca import --cert <path> --key <path>` | Import an existing CA certificate and private key |
| `reactor-ca ca passwd` | Change the master password for all encrypted keys |

### Host Certificate Management

| Command | Description |
|---------|-------------|
| `reactor-ca host issue <host-id>` | Issue/renew a certificate for a host |
| `reactor-ca host issue --all` | Issue/renew certificates for all hosts |
| `reactor-ca host issue <host-id> --rekey` | Force generation of a new private key |
| `reactor-ca host issue <host-id> --deploy` | Issue and deploy certificate in one step |
| `reactor-ca host list` | List all host certificates with their status |
| `reactor-ca host list --expired` | Show only expired certificates |
| `reactor-ca host list --expiring-in 30` | Show certificates expiring in next 30 days |
| `reactor-ca host list --json` | Output in JSON format |
| `reactor-ca host info <host-id>` | Display detailed certificate information |
| `reactor-ca host deploy <host-id>` | Run deployment command for a host |
| `reactor-ca host deploy --all` | Deploy all host certificates |
| `reactor-ca host export-key <host-id>` | Export unencrypted private key to stdout |
| `reactor-ca host export-key <host-id> -o file.key` | Export private key to file |
| `reactor-ca host import-key <host-id> --key <path>` | Import existing private key |
| `reactor-ca host sign-csr --csr <path> --out <path>` | Sign external CSR |
| `reactor-ca host clean` | Remove certificates for hosts no longer in config |

### Configuration Management

| Command | Description |
|---------|-------------|
| `reactor-ca config validate` | Validate configuration files |

## Common Workflows

### New CA Workflow

```bash
# Initialize configuration
./reactor-ca init

# Edit configuration
vim config/ca.yaml

# Create the CA
./reactor-ca ca create

# Edit host configuration
vim config/hosts.yaml

# Issue certificates
./reactor-ca host issue web-server-example
```

### Import Existing CA

```bash
# Initialize configuration (optional)
./reactor-ca init

# Import existing CA
./reactor-ca ca import --cert path/to/ca.crt --key path/to/ca.key

# Edit host configuration
vim config/hosts.yaml

# Issue certificates
./reactor-ca host issue web-server-example
```

### Certificate Renewal

```bash
# Renew a specific certificate
./reactor-ca host issue web-server-example

# Renew all certificates
./reactor-ca host issue --all

# Renew and deploy
./reactor-ca host issue web-server-example --deploy
```

### Key Rotation

```bash
# Rotate the CA key and certificate
./reactor-ca ca rekey

# Rotate a specific host key and certificate
./reactor-ca host issue web-server-example --rekey

# Rotate all host keys and certificates
./reactor-ca host issue --all --rekey
```

## Configuration

### CA Configuration (`config/ca.yaml`)

```yaml
ca:
  # Subject details for the CA certificate
  subject:
    common_name: "Reactor Homelab CA"
    organization: "Reactor Industries"
    organization_unit: "IT Department"
    country: "DE"
    state: "Berlin"
    locality: "Berlin"
    email: "admin@reactor.dev"

  # Certificate validity
  validity:
    years: 10

  # Cryptographic settings
  key_algorithm: "ECP384"    # RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519
  hash_algorithm: "SHA384"   # SHA256, SHA384, SHA512

  # Password management
  password:
    min_length: 12
    env_var: "REACTOR_CA_PASSWORD"  # Environment variable for password
    # file: "/path/to/password/file"  # Optional: password file path
```

### Hosts Configuration (`config/hosts.yaml`)

```yaml
hosts:
  web-server-example:
    subject:
      common_name: "web.reactor.local"
    
    # Subject Alternative Names
    alternative_names:
      dns:
        - "web.reactor.local"
        - "grafana.reactor.local"
      ip:
        - "192.168.1.100"
        - "10.10.0.1"
    
    # Certificate validity
    validity:
      years: 1
    
    # Cryptographic settings (optional, defaults to CA settings)
    key_algorithm: "RSA2048"
    hash_algorithm: "SHA256"
    
    # Export paths (optional). These paths can be used in the deploy commands.
    export:
      cert: "/etc/ssl/certs/web-server.pem"
      chain: "/etc/ssl/certs/web-server-chain.pem"
    
    # Deployment commands (optional). Executed as a shell script.
    # Variables:
    # - ${cert}: Path to the exported certificate.
    # - ${chain}: Path to the exported chain file.
    # - ${private_key}: Path to a temporary, unencrypted private key file (securely handled).
    deploy:
      commands:
        - "echo 'Reloading NGINX...'"
        - "systemctl reload nginx"
```

## Store Structure

```
store/
├── ca/
│   ├── ca.crt         # CA certificate (PEM format)
│   └── ca.key.enc     # Encrypted CA private key (PKCS#8, AES-256-GCM)
├── hosts/
│   └── <host-id>/
│       ├── cert.crt   # Host certificate (PEM format)
│       └── cert.key.enc # Encrypted host private key
└── ca.log             # Operation log
```

## Cryptographic Options

### Supported Key Algorithms

| Algorithm | Key Size | Performance | Security | Compatibility |
|-----------|----------|-------------|-----------|---------------|
| RSA2048   | 2048-bit | Medium      | Good      | Excellent     |
| RSA3072   | 3072-bit | Slow        | Strong    | Excellent     |
| RSA4096   | 4096-bit | Slow        | Very Strong| Excellent     |
| ECP256    | P-256    | Fast        | Strong    | Good          |
| ECP384    | P-384    | Medium      | Very Strong| Good          |
| ECP521    | P-521    | Medium      | Very Strong| Good        |
| ED25519   | 256-bit  | Very Fast   | Strong    | Modern only   |

### Supported Hash Algorithms

- **SHA256**: Good default, excellent compatibility
- **SHA384**: Stronger, recommended for ECP384 and higher
- **SHA512**: Strongest, for high-security environments

### Subject Alternative Name Types

ReactorCA supports multiple SAN types:

```yaml
alternative_names:
  dns:
    - "example.com"
    - "*.example.com"
  ip:
    - "192.168.1.100"
    - "2001:db8::1"
  email:
    - "admin@example.com"
  uri:
    - "https://example.com"
```

## Password Management

ReactorCA supports multiple password sources (checked in order):

1. **Password File**: Specified in `ca.yaml` under `password.file`
2. **Environment Variable**: Set via `REACTOR_CA_PASSWORD` (or custom env var)
3. **Interactive Prompt**: Secure terminal input (fallback)

## Security Features

- All private keys encrypted at rest with PKCS#8 + AES-256-GCM
- Strong key derivation function (PBKDF2) with high iteration count
- Temporary files use secure permissions (0600) and automatic cleanup
- Deployment scripts are executed securely without exposing keys
- Master password required for all private key operations

## Development Environment

This project uses `devenv.nix` for reproducible development:

```bash
# Enter development shell
devenv shell

# Build and test
go build -v ./cmd/reactor-ca
go test -v ./...
```

## Limitations

ReactorCA is designed for homelab use and has some intentional limitations:

- No certificate revocation (CRL/OCSP) support
- No PKCS#12 bundle creation
- No automated renewal daemon (use cron/systemd timers)
