![ReactorCA screenshot](docs/assets/help_screen.webp)

![Go CI](https://github.com/serpent213/reactor-ca/workflows/CI/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-63.2%25-yellow)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD_2_Clause-yellow.svg)](https://opensource.org/license/bsd-2-clause)

# ReactorCA

**Currently in development – expect breaking changes!**

A Go CLI tool to manage a homelab/small-office Certificate Authority with [age](https://age-encryption.org/) encrypted private keys.

Typical usage scenario: Run it on your desktop to renew and deploy certificates for your LAN/VPN devices once a year or once a month, while keeping your CA store and config in a Git repo.

## Features

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts
- Strong key encryption with multiple providers:
  - Password-based encryption using age with scrypt key derivation
  - SSH key-based encryption using existing SSH identities (age-ssh)
  - Hardware token encryption using age plugins (Secure Enclave, YubiKey, etc.)
- Certificate inventory and expiration tracking
- Simple deployment to target locations via shell scripts
- Single statically-linked binary with no runtime dependencies

## Motivation and Design Targets

- **Command-line focused**: [XCA](https://www.hohnstaedt.de/xca/) is a great tool for GUI-centric workflows, while ReactorCA is built for automation and scripting in mind
- **Modern implementation**: Classics like [easy-ca](https://github.com/redredgroovy/easy-ca) don't always integrate well with modern environments
- **Secure by default**: Strong encryption, secure key storage, and sane defaults built-in
- **Plug & play**: Minimal configuration required to get started
- **Domain knowledge**: Provide a friendly ecosystem and knowledge base for administrators to practically implement a home-brew PKI

## Cryptographic Implementation

ReactorCA is built on proven cryptographic foundations:

### Core Libraries
- **Go Standard Crypto**: Uses `crypto/x509` for certificate operations, `crypto/rsa` and `crypto/ecdsa` for key generation (RSA 2048-4096, ECDSA P-256/384/521, Ed25519), and `crypto/rand` for secure randomness
- **age Encryption**: Modern file encryption using [Filippo Valsorda's age library](https://github.com/FiloSottile/age) for private key protection

### Key Protection
Every `.key.age` file is encrypted using one of two methods:

**Password-based encryption**:
- **ChaCha20-Poly1305**: Modern authenticated encryption for private keys
- **scrypt**: Strong password-based key derivation
- **age format**: Battle-tested encryption with simple, secure design

**SSH key-based encryption** (age-ssh):
- Uses existing SSH private keys as age identities
- SSH public keys serve as age recipients
- Leverages proven SSH key infrastructure
- Supports Ed25519, RSA, and ECDSA SSH keys

**Hardware token encryption** (age plugins):
- Uses age-plugin-* binaries for hardware token support
- Secure Enclave integration (macOS)
- YubiKey support
- Future-proof plugin architecture for new hardware

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/your-org/reactor-ca/releases).

### Build from Source

```bash
git clone https://github.com/serpent213/reactor-ca.git
cd reactor-ca
go build -o ca ./cmd/ca
```

## Quick Start

### 1. Initialize Configuration

First, create the default config files:

```bash
ca init
```

ReactorCA automatically detects your SSH keys and configures encryption accordingly:
- **SSH keys found**: Uses SSH-based encryption (prefers Ed25519 over RSA)
- **No SSH keys**: Falls back to password-based encryption

This creates configuration files in the `config/` directory. Edit them according to your needs.

### 2. Create CA Certificate

After editing the configuration, create the CA:

```bash
ca ca create
```

This creates a self-signed CA certificate and private key (encrypted with the password you provide).

### 3. Issue Host Certificate

To issue a certificate for a host defined in your hosts.yaml:

```bash
ca host issue web-server-example
```

### 4. List Certificates

To list all certificates with their expiration dates:

```bash
ca host list
```

### 5. Export and Deploy Certificates

ReactorCA supports flexible certificate export and deployment:

**Export only** (automatic during certificate issuance):
```bash
ca host issue web-server-example  # Exports to configured paths automatically
```

**Deploy only** (run deployment commands independently):
```bash
ca host deploy web-server-example  # Runs deployment without re-issuing
```

**Issue, export and deploy together**:
```bash
ca host issue web-server-example --deploy  # Issue certificate then deploy
```

Deploy will create temp files if the required files are not exported, so `export` and `deploy` options can be used independently from each other.

## CLI Reference

### Global Flags

- `--root <path>` - Root directory for config and store (env: `REACTOR_CA_ROOT`)

### CA Management

| Command | Description |
|---------|-------------|
| `ca ca create` | Create a new CA key and self-signed certificate |
| `ca ca renew` | Renew the CA certificate using the existing key |
| `ca ca rekey` | Create a new key and certificate, replacing the old ones |
| `ca ca info` | Display detailed information about the CA certificate |
| `ca ca import --cert <path> --key <path>` | Import an existing CA certificate and private key |
| `ca ca passwd` | Change the master password for all encrypted keys |

### Host Certificate Management

| Command | Description |
|---------|-------------|
| `ca host issue <host-id>` | Issue/renew a certificate for a host |
| `ca host issue --all` | Issue/renew certificates for all hosts |
| `ca host issue <host-id> --rekey` | Force generation of a new private key |
| `ca host issue <host-id> --deploy` | Issue and deploy certificate in one step |
| `ca host list` | List all host certificates with their status |
| `ca host list --expired` | Show only expired certificates |
| `ca host list --expiring-in 30` | Show certificates expiring in next 30 days |
| `ca host list --json` | Output in JSON format |
| `ca host info <host-id>` | Display detailed certificate information |
| `ca host deploy <host-id>` | Run deployment command for a host |
| `ca host deploy --all` | Deploy all host certificates |
| `ca host export-key <host-id>` | Export unencrypted private key to stdout |
| `ca host export-key <host-id> -o file.key` | Export private key to file |
| `ca host import-key <host-id> --key <path>` | Import existing private key |
| `ca host sign-csr --csr <path> --out <path>` | Sign external CSR |
| `ca host clean` | Remove certificates for hosts no longer in config |

### Configuration Management

| Command | Description |
|---------|-------------|
| `ca config validate` | Validate configuration files |

## Common Workflows

### New CA Workflow

```bash
# Initialize configuration
ca init

# Edit configuration
vim config/ca.yaml

# Create the CA
ca ca create

# Edit host configuration
vim config/hosts.yaml

# Issue certificates
ca host issue web-server-example
```

### Import Existing CA

```bash
# Initialize configuration (optional)
ca init

# Import existing CA
ca ca import --cert path/to/ca.crt --key path/to/ca.key

# Edit host configuration
vim config/hosts.yaml

# Issue certificates
ca host issue web-server-example
```

### Certificate Renewal

```bash
# Renew a specific certificate
ca host issue web-server-example

# Renew all certificates
ca host issue --all

# Renew and deploy
ca host issue web-server-example --deploy
```

### Key Rotation

```bash
# Rotate the CA key and certificate
ca ca rekey

# Rotate a specific host key and certificate
ca host issue web-server-example --rekey

# Rotate all host keys and certificates
ca host issue --all --rekey
```

## Emergency Access

If ReactorCA cannot be run, you can manually decrypt private keys using the `age` command:

```bash
# Decrypt CA private key (SSH-based encryption)
age -d -i ~/.ssh/id_ed25519 store/ca/ca.key.age > ca.key

# Decrypt host private key
age -d -i ~/.ssh/id_ed25519 store/hosts/web-server/cert.key.age > host.key
```

The store structure is simple: certificates are in PEM format (`.crt` files) and private keys are age-encrypted (`.key.age` files). Your encryption method determines which identity file to use with `age -d -i`.

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

# Encryption configuration
encryption:
  provider: "password"  # password | ssh | plugin
  password:
    min_length: 12
    env_var: "REACTOR_CA_PASSWORD"
  ssh:
    identity_file: "~/.ssh/id_ed25519"  # SSH private key for decryption
    recipients:  # SSH public keys for encryption
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host"
      - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgExample user@host"
  plugin:
    identity_file: "~/.age/plugin-identity.txt"  # age plugin identity
    recipients:  # age plugin recipients
      - "age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwgjgtev8"  # Secure Enclave
      - "age1yubikey1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwgjgtev8"  # YubiKey
```

### Hosts Configuration (`config/hosts.yaml`)

Host certificates inherit CA subject fields (organization, country, etc.) when not specified, **except** `common_name` which must be explicitly set for each host, if desired.

In that case, `common_name` must also be listed in `alternative_names.dns`. [RFC 2818](https://datatracker.ietf.org/doc/html/rfc2818#section-3.1) (2000) deprecates the use of Common Name for host identities.

```yaml
hosts:
  web-server-example:
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

    # Export paths (optional) - files written during 'host issue'
    export:
      cert: "/etc/ssl/certs/web-server.pem"           # Certificate in PEM format
      chain: "/etc/ssl/certs/web-server-chain.pem"    # Certificate + CA chain
      key_encrypted: "/etc/ssl/private/web-server.key.age"  # Encrypted private key (age format)

    # Deployment commands (optional) - executed during 'host deploy'
    # Deploy can run independently or together with issue (--deploy flag)
    # Variables available:
    # - ${cert}: Certificate file (from export.cert or temporary file)
    # - ${chain}: Certificate chain (from export.chain or temporary file)
    # - ${key_encrypted}: Encrypted private key (from export.key_encrypted or temporary file)
    # - ${private_key}: Temporary unencrypted private key (secure, auto-cleanup)
    deploy:
      command: |
        echo 'Deploying certificates...'
        scp ${cert} ${chain} server:/etc/ssl/
        ssh server systemctl reload nginx
```

## Store Structure

```
store/
├── ca/
│   ├── ca.crt         # CA certificate (PEM format)
│   └── ca.key.age     # age-encrypted CA private key
├── hosts/
│   └── <host-id>/
│       ├── cert.crt   # Host certificate (PEM format)
│       └── cert.key.age # age-encrypted host private key
└── ca.log             # Operation log
```

## Cryptographic Options

### Supported Key Algorithms

| Algorithm | Key Size | Performance | Security    | Compatibility |
|-----------|----------|-------------|-------------|---------------|
| RSA2048   | 2048-bit | Medium      | Good        | Excellent     |
| RSA3072   | 3072-bit | Slow        | Strong      | Excellent     |
| RSA4096   | 4096-bit | Slow        | Very Strong | Excellent     |
| ECP256    | P-256    | Fast        | Strong      | Good          |
| ECP384    | P-384    | Medium      | Very Strong | Good          |
| ECP521    | P-521    | Medium      | Very Strong | Good          |
| ED25519   | 256-bit  | Very Fast   | Strong      | Modern only   |

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

## Key Protection and Authentication

ReactorCA supports multiple encryption providers for private key protection:

### Password-based Encryption (default)
Password sources are checked in order:
1. **Password File**: Specified in `ca.yaml` under `password.file`
2. **Environment Variable**: Set via `REACTOR_CA_PASSWORD` (or custom env var)
3. **Interactive Prompt**: Secure terminal input (fallback)

### SSH Key-based Encryption (age-ssh)
Uses existing SSH infrastructure for key protection:
- **Identity File**: Your SSH private key (e.g., `~/.ssh/id_ed25519`)
- **Recipients**: SSH public keys that can decrypt the private keys
- **Supports**: Ed25519, RSA, and ECDSA SSH keys
- **No passwords required**: Leverages SSH agent or unlocked SSH keys

### Hardware Token Encryption (age plugins)
Uses age plugins for hardware-backed key protection:
- **Identity File**: Plugin identity file (e.g., `~/.age/plugin-identity.txt`)
- **Recipients**: Hardware token public keys (e.g., Secure Enclave, YubiKey)
- **Supports**: Any age-plugin-* binary (secure-enclave, yubikey, tpm, etc.)
- **Hardware security**: Private keys never leave the secure hardware

## Intermediate CAs

Currently, ReactorCA is primarily designed for a very basic setup: A single root CA directly signs all certificates without intermediaries. But you should be fine creating an intermediate CA manually and importing it into ReactorCA, then use it for your everyday operation.

## agenix integration

If you are using [agenix](https://github.com/ryantm/agenix) (or a similar system) for secret distribution, you can share secrets between ReactorCA and agenix, usually by employing the `additional_recipients` option. Note that password encryption does NOT mix with age-ssh or plugin modes for security reasons.

## Development Environment

This project uses `devenv.nix` for reproducible development and *Just* as build helper:

```bash
# Enter development shell
devenv shell

# Build, lint and test
just build
just lint
just test
./ca --version
```

## Limitations

- No certificate revocation (CRL/OCSP) support
- No PKCS#12 bundle creation
- No automated renewal daemon (use cron/systemd timers)
- Date calculations use fixed multipliers, i.e. 1 year = 365 days, 1 month = 30 days
