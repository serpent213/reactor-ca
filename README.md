# ReactorCA

**Currently in ALPHA state, use at your own risk!**

A Python CLI tool to manage a homelab Certificate Authority.

Typical usage scenario: Run it on your desktop to renew and deploy certificates for your LAN/VPN devices once a year.

## Features

- Create and manage a self-signed Certificate Authority
- Generate and renew certificates for hosts
- Strong key encryption with password protection
- Certificate inventory cache
- Certificate chain support (CA + host certificate)
- Flexible password options (prompt, environment variable, file)
- Export unencrypted private keys when needed
- Simple deployment to target locations
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
ca config init
```

This will create default configuration files in the `config/` directory. Edit them according to your needs.

> **Note**: The `config` directory is excluded from version control. Example configurations can be found in the `example_config` directory for reference.

### Create CA Certificate

After editing the configuration, create the CA:

```bash
ca ca create
```

This will create a self-signed CA certificate and private key (encrypted with the password you provide).

### Issue Host Certificate

To issue a certificate for a host defined in your hosts.yaml:

```bash
ca host issue hostname
```

### List Certificates

To list all certificates with their expiration dates:

```bash
ca host list
```

### Renew Certificates

To renew a specific certificate:

```bash
ca host issue hostname
```

Or to renew all certificates:

```bash
ca host issue --all
```

### Change Password

To change the password for all encrypted private keys:

```bash
ca util passwd
```

## Common Workflows

### New CA Workflow

```bash
# Initialize configuration
ca config init

# Edit configuration
vim config/ca.yaml

# Create the CA
ca ca create

# Create host config
vim config/hosts.yaml

# Issue certificates
ca host issue server1
```

### Import CA Workflow

```bash
# Initialize configuration (optional)
ca config init

# Import existing CA
ca ca import --cert path/to/ca.crt --key path/to/ca.key

# Create host config
vim config/hosts.yaml

# Issue certificates
ca host issue server1
```

### Import Host Keys Workflow

```bash
# Import existing key
ca host import server1 --key path/to/key.pem

# Finalize host config
vim config/hosts.yaml

# Issue certificate using imported key
ca host issue server1
```

### Key Rotation Workflow

```bash
# Rotate the CA key and certificate
ca ca rekey

# Rotate a specific host key and certificate
ca host rekey server1

# Rotate all host keys and certificates
ca host rekey --all
```

### Deploy Certificates

```bash
# Deploy a specific certificate
ca host deploy server1

# Deploy all certificates
ca host deploy --all

# Issue and deploy in one step
ca host issue server1 --deploy
```

## Configuration

### CA Configuration

The CA configuration is stored in `config/ca.yaml`:

```yaml
ca:
  common_name: "Reactor CA"
  organization: "Reactor Homelab"
  organization_unit: "IT"
  country: "DE"
  state: "Berlin"
  locality: "Berlin"
  email: "admin@example.com"
  key_algorithm: "RSA4096"
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

Host certificates are configured in `config/hosts.yaml`. Hosts are defined in a dictionary where the key is a unique host ID.

```yaml
hosts:
  server1:
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
    key_algorithm: "RSA2048"
```

#### Deployment Commands

When configuring host certificates in `hosts.yaml`, you can specify a `deploy.command` that will be executed after issuing or renewing a certificate. This command supports the following variable substitutions:

- `${cert}` - Will be replaced with the absolute path to the certificate file in the store.
- `${private_key}` - Will be replaced with the absolute path to a temporary file containing the decrypted private key. This temporary file is created with secure permissions (readable only by the owner) and is automatically removed after the command completes.

Example:
```yaml
deploy:
  command: "cp ${cert} /etc/nginx/ssl/server.pem && cp ${private_key} /etc/nginx/ssl/server.key && systemctl reload nginx"
```

**Security Note:** The deployment command is parsed and executed safely, avoiding shell injection vulnerabilities.

## Cryptographic Options

### Key Types

ReactorCA supports the following key types:

1. **RSA**
   - Traditional asymmetric algorithm
   - Specify key size (e.g., RSA2048, RSA4096)

2. **EC (Elliptic Curve)**
   - More efficient than RSA with smaller key sizes
   - Specify curve (e.g., ECP256, ECP384, ECP521)

3. **ED25519**
   - Modern Edwards-curve algorithm

4. **ED448**
   - Higher security Edwards-curve algorithm

### Performance Implications

Different algorithms impact TLS handshake performance:

     Algorithm     Handshake Speed   CPU Load   Security      Notes
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     RSA-2048      Medium            Medium     Adequate      Legacy support
     RSA-4096      Slow              High       Strong        CPU-intensive
     ECDSA P-256   Fast              Low        Strong        Good balance
     ECDSA P-384   Medium            Medium     Stronger      More CPU than P-256
     Ed25519       Very Fast         Very Low   Strong        Modern choice
     Ed448         Fast              Low        Very Strong   Overkill for most

### Hash Algorithms

ReactorCA supports multiple hash algorithms for certificate signatures:

1. **SHA256**
   - Default option, good balance of security and compatibility
   - Example: `hash_algorithm: "SHA256"`

2. **SHA384**
   - Stronger hash, recommended for use with EC P-384
   - Example: `hash_algorithm: "SHA384"`

3. **SHA512**
   - Strongest hash, recommended for high-security certificates
   - Example: `hash_algorithm: "SHA512"`

## Subject Alternative Name (SAN) Types

ReactorCA supports a wide range of SAN types:

1. **DNS Names**
   ```yaml
   dns:
     - "example.com"
     - "www.example.com"
   ```

2. **IP Addresses** (IPv4 and IPv6)
   ```yaml
   ip:
     - "192.168.1.10"
     - "2001:db8::1"
   ```

3. **Email Addresses**
   ```yaml
   email:
     - "admin@example.com"
   ```

4. **URIs**
   ```yaml
   uri:
     - "https://example.com"
   ```

5. **Directory Names** (Distinguished Names)
   ```yaml
   directory_name:
     - "CN=example,O=Example Inc,C=US"
   ```

6. **Registered IDs** (OIDs)
   ```yaml
   registered_id:
     - "1.3.6.1.4.1.311.20.2.3"
   ```

7. **Other Names** (Custom OIDs with values)
   ```yaml
   other_name:
     - "1.3.6.1.4.1.311.20.2.3:Custom Value"
   ```

## Compatibility Considerations

- **RSA 2048+ with SHA256** has excellent compatibility with all browsers
- **EC P-256/P-384 with SHA256** works with all modern browsers (5+ years old)
- **ED25519/ED448 and SHA384/SHA512** may have limited compatibility with very old clients
- For maximum compatibility, use RSA 2048 with SHA256
- For future-proofing with good compatibility, use EC P-384 with SHA384
- For highest security, use ED448 with SHA512

## Password Management Options

ReactorCA offers several ways to provide the master password:

1. **Interactive Prompt** (default): The tool will ask for the password when needed
2. **Environment Variable**: Set the `REACTOR_CA_PASSWORD` environment variable
3. **Password File**: Specify a file path in the `ca.yaml` file's `password.file` setting

The tool tries these methods in order: file, environment variable, interactive prompt.

## Development

### Linting & Testing

```bash
poetry run check
```

## Limitations and Future Work

ReactorCA is designed for homelab use and has some limitations:

- No revocation/CRL support
- No PKCS#12 support
- No automation for rekeying/key deployment
