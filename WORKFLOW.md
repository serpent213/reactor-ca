# ReactorCA Workflow Analysis and Improvements

## Current Workflow Issues

After analyzing the current ReactorCA design, I've identified several areas for improvement:

1. **Command Naming Inconsistency**: The verbs "generate" and "renew" perform similar operations but with different contexts, potentially confusing users.

2. **Data Duplication**: Possible duplication between inventory and config files could lead to inconsistencies.

3. **CA Renewal**: No clear workflow for renewing the CA certificate.

4. **Import Workflows**: The process for importing existing CAs and keys lacks clarity.

5. **Command Structure**: Some commands have dual purposes (e.g., `init` for both creating configs and generating CA).

## User Story Analysis

### User Story 1: New CA from Scratch
Current workflow requires running `init` twice with different purposes:
- First to create config templates
- Second to actually generate the CA certificate

### User Story 2: Import Existing CA and Host Keys
Current workflow:
- No clear path for importing an existing CA certificate and key
- No process for extracting CA attributes to update config
- Importing host keys appears possible but the workflow isn't clearly defined

## Suggested Improvements

### 1. Restructured Command Hierarchy

```
ca
├── config       # Configuration management
│   ├── init     # Generate initial config files
│   └── validate # Validate config files
├── ca           # CA management
│   ├── create   # Create a new CA
│   ├── import   # Import existing CA (cert+key)
│   ├── renew    # Renew the CA certificate
│   ├── rekey    # Generate new key and renew CA certificate
│   └── info     # Show CA info
├── host         # Host certificate operations
│   ├── issue    # Issue/renew certificates (unified command)
│   ├── import   # Import existing key
│   ├── rekey    # Generate new key and issue certificate
│   ├── list     # List all certificates
│   ├── deploy   # Deploy to destination
│   └── sign     # Utility to sign CSRs (standalone operation)
└── util         # Utility operations
    └── passwd   # Change encryption password
```

### 2. Detailed Command Options

#### Configuration Management

##### `ca config init`
```bash
ca config init
```
- No options, bail out in case config files already exist.

##### `ca config validate`
```bash
ca config validate
```
- No options, we will introduce more tooling later on for YAML schema validation, so it's ok to leave this mainly a stub for now. Still our internal validator shall be called already by other actions that rely on a valid config.

#### CA Management

##### `ca ca create`
```bash
ca ca create
```
- No options, everything is given in the config. The CA config may specify a "no password" flag - in that case neither the CA key nor the host private keys will be encrypted (INSECURE!).
- Ask for encryption password (with confirmation) unless in "no password" mode.

##### `ca ca import`
```bash
ca ca import --cert CERT_FILE --key KEY_FILE
```
- `--cert CERT_FILE`: Path to the CA certificate to import
- `--key KEY_FILE`: Path to the CA private key to import
- Bail out if ca_config or cert or key file already exist.
- In case the key file is password protected ask the user for the decryption password. In any case ask for the encryption password for storing it (with confirmation).

##### `ca ca renew`
```bash
ca ca renew
```
- No options, everything is given in the config.
- Renews the certificate using the existing key.

##### `ca ca rekey`
```bash
ca ca rekey
```
- No options, everything is given in the config.
- Generates a new private key and creates a new certificate with the same information.
- Both operations (generating a new key and creating a new certificate) are atomic.

##### `ca ca info`
```bash
ca ca info [--json]
```
- `--json`: Output in JSON format instead of human-readable text

#### Host Certificate Operations

##### `ca host issue`
```bash
ca host issue [HOSTNAME] [--all]
```
- `HOSTNAME`: The hostname to issue a certificate for
- `--all`: Issue or renew certificates for all configured hosts

##### `ca host import`
```bash
ca host import HOSTNAME --key KEY_FILE
```
- `HOSTNAME`: The hostname to associate with this key
- `--key KEY_FILE`: Path to the private key to import
- Ask for decryption password if necessary.
- Bail out if host already exists (files or in config).

##### `ca host rekey`
```bash
ca host rekey HOSTNAME [--all]
```
- `HOSTNAME`: The hostname to rekey
- `--all`: Rekey all host certificates
- Generates a new private key and issues a new certificate for the host(s).
- Both operations (generating a new key and issuing a new certificate) are atomic.

##### `ca host list`
```bash
ca host list [--expired] [--expiring DAYS] [--json]
```
- `--expired`: Only show expired certificates
- `--expiring DAYS`: Show certificates expiring within specified days
- `--json`: Output in JSON format
- Output sorted by hostname.

##### `ca host deploy`
```bash
ca host deploy [HOSTNAME] [--all]
```
- `HOSTNAME`: The hostname to deploy certificate for
- `--all`: Deploy all certificates

##### `ca host sign-csr`
```bash
ca host sign-csr --csr CSR_FILE --out CERT_FILE [--validity DAYS]
```
- `--csr CSR_FILE`: Path to CSR file to sign
- `--out CERT_FILE`: Output path for the signed certificate
- `--validity DAYS`: Validity period in days (default to 365 days)
- Display CSR details before signing

#### Utility Operations

##### `ca util passwd`
```bash
ca util passwd
```
- Ask for old and new password (with confirmation) and reencrypt all CA and host keys (bail out if disabled in CA config).

### 3. Unified Certificate Operations

Replace the separate "generate" and "renew" operations with a single "issue" command that determines the appropriate action based on context:

```bash
# Issue new or renew existing certificate
ca host issue server1.example.com

# Issue/renew all certificates
ca host issue --all
```

### 4. Key Rotation Support

Add support for key rotation through the "rekey" commands:

```bash
# Rotate CA key and certificate
ca ca rekey

# Rotate a host key and certificate
ca host rekey server1.example.com

# Rotate all host keys and certificates
ca host rekey --all
```

### 5. Simplified Data Management

- **Primary Source**: `hosts.yaml` for configuration
- **Derived Data**: `inventory.yaml` as a cache/index only
- **Auto-Rebuilding**: Automatically rebuild inventory when needed
- **No Duplication**: Don't store configuration data in inventory

### 6. CSR Handling as a Standalone Utility

Treat CSR signing as a simple utility operation that doesn't interact with the certificate store or configuration:

```bash
# Sign a CSR with the CA and output the certificate to a file
ca host sign-csr --csr path/to/request.csr --out path/to/output.crt
```

This operation would:
1. Read the CSR file
2. Sign it with the CA certificate and key
3. Write the signed certificate to the specified output file
4. Not store any information in the inventory
5. Not interact with host configurations

### 7. Improved Workflows

#### New CA Workflow
```bash
# Initialize configuration
ca config init

# Edit configuration
vim config/ca_config.yaml

# Create the CA
ca ca create

# Create host config
vim config/hosts.yaml

# Issue certificates
ca host issue server1.example.com
```

#### Import CA Workflow
```bash
# Initialize configuration (optional)
ca config init

# Import existing CA (updates or creates config automatically)
ca ca import --cert path/to/ca.crt --key path/to/ca.key

# Create host config
vim config/hosts.yaml

# Issue certificates
ca host issue server1.example.com
```

#### Import Host Keys Workflow
```bash
# Import existing key (creates config entry if needed)
ca host import server1.example.com --key path/to/key.pem

# Finalise host config
vim config/hosts.yaml

# Issue certificate using imported key
ca host issue server1.example.com
```

#### CSR Workflow (Edge Case)
```bash
# External system generates CSR and sends it to ReactorCA operator

# Sign the CSR as a one-off operation
ca host sign-csr --csr path/to/request.csr --out path/to/signed.crt
```

#### Renewal Workflow
```bash
# Renew a specific certificate
ca host issue server1.example.com

# Renew all certificates
ca host issue --all
```

#### Key Rotation Workflow
```bash
# Rotate the CA key and certificate
ca ca rekey

# Rotate a specific host key and certificate
ca host rekey server1.example.com

# Rotate all host keys and certificates
ca host rekey --all
```

## Summary

These changes create a more intuitive, consistent command structure while reducing data duplication and clarifying workflows. The unified "issue" command eliminates confusion between generation and renewal operations, while the new "rekey" commands provide clear pathways for key rotation.

By treating CSR signing as a standalone utility, we keep the main certificate management process clean and simple. This approach acknowledges that CSR handling is an edge case for most homelab users while still providing the necessary functionality when needed.

The proposed structure supports three primary models:
1. **Self-contained**: ReactorCA manages keys and certificates (primary use case)
2. **Key rotation**: Clear process for rotating keys while maintaining certificate information
3. **One-off signing**: Simple utility to sign CSRs when needed (edge case)

The consistent command-line interface with predictable option patterns makes the tool easier to learn and use, with options that follow common patterns like `--all` and `--json`.

Config files will only be touched upon "import" actions after being confirmed by the user. We take care to edit the config files carefully, keeping user comments, for example. For all newly created YAML files, make sure to include a remark at the top explaining how the file will be treated by us, if it can safely be deleted or updated by the user etc. We treat the certificate store `certs/` as "write only", except for when our inventory file goes missing, in that case we need to scan it (no need for any timestamp comparisions, as was suggested in an earlier approach).

Passwords - we want to make sure, only one password is being used for encrypting the various (ca/host) key files. To ensure that, before encrypting a key we validate the user supplied password against the encrypted CA key (unless in "no password" mode, of course).
