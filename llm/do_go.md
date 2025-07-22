# Product Requirements Document: Reactor-CA (Go)

## 1. Introduction

### 1.1. Purpose

This document outlines the requirements for a full reimplementation of the `ReactorCA` tool in the Go programming language. The new tool, `reactor-ca`, will provide a secure, reliable, and user-friendly Command-Line Interface (CLI) for managing a private Public Key Infrastructure (PKI) suitable for homelab and small-to-medium business environments.

The primary goals of this reimplementation are:
-   **Portability:** Produce a single, static, cross-platform binary with no external runtime dependencies.
-   **Performance:** Leverage Go's performance for fast cryptographic operations and CLI responsiveness.
-   **Maintainability:** Implement a clean, well-tested, and modular codebase.
-   **Refined User Experience:** Create a clean, consistent, and orthogonal CLI structure that is intuitive for users.

### 1.2. Target Audience

-   Homelab administrators and tech enthusiasts.
-   Developers and SREs managing internal services and development environments.
-   Anyone needing a simple, file-based, self-hosted Certificate Authority.

## 2. Core Concepts

### 2.1. Stateless Command Execution

The `reactor-ca` tool must operate on a stateless, per-command basis. Each execution of a command is an independent process that:
1.  Initializes its state by reading from configuration files and the on-disk store.
2.  If required, obtains the master password via file, environment variable, or interactive prompt.
3.  Performs its designated cryptographic or file management operations.
4.  Writes any changes (new keys, certificates) back to the on-disk store.
5.  Exits with a clear status message and an appropriate exit code.

The application must not rely on running daemons, background services, or in-memory state that persists between command invocations.

### 2.2. Configuration-Driven

All certificate parameters and application settings shall be defined declaratively in YAML configuration files. This allows for version control, auditing, and easy replication of the PKI setup.

-   **`config/ca.yaml`**: Defines the properties of the root Certificate Authority.
-   **`config/hosts.yaml`**: Defines the properties for each host (leaf) certificate to be issued.

### 2.3. Secure On-Disk Store

All sensitive cryptographic material and generated certificates are stored in a well-defined directory structure, referred to as the "store".

-   All private keys (CA and host) must be stored on disk in an encrypted format (e.g., PKCS#8 with AES-256-CBC encryption).
-   A single master password is used to encrypt and decrypt all private keys in the store.
-   Store/config root path can be set with `--root` option or via environment `REACTOR_CA_ROOT` - if neither is given, default to current directory.

### 2.4. Master Password Management

The master password is required for any operation involving private keys. The application must support retrieving the password in the following order of precedence:
1.  **Password File:** From a file specified in `config/ca.yaml`.
2.  **Environment Variable:** From an environment variable (e.g., `REACTOR_CA_PASSWORD`).
3.  **Interactive Prompt:** As a fallback, securely prompt the user for the password.

## 3. User Interface (CLI)

The CLI should be clean, consistent, and discoverable. The proposed command structure is organized into logical groups (`ca`, `host`, `config`).

| Command | Description |
| :--- | :--- |
| `reactor-ca init` | Initialize `config` and `store` directories in the current location. |
| `reactor-ca --root <path> ...` | Global flag to specify the root directory for `config` and `store`. |
| **CA Management** | |
| `reactor-ca ca create` | Create a new CA key and self-signed certificate. |
| `reactor-ca ca renew` | Renew the CA certificate using the existing key. |
| `reactor-ca ca rekey` | Create a new key and a new self-signed certificate, retiring the old ones. |
| `reactor-ca ca import --cert <path> --key <path>` | Import an existing CA certificate and private key into the store. |
| `reactor-ca ca info` | Display detailed information about the CA certificate. |
| `reactor-ca ca passwd` | Change the master password for all encrypted keys in the store. |
| **Host Certificate Management** | |
| `reactor-ca host issue <host-id|--all>` | Issue/renew a certificate for one or all hosts defined in `hosts.yaml`. |
| `reactor-ca host issue <host-id> --rekey` | Force generation of a new private key before issuing the certificate. |
| `reactor-ca host list` | List all host certificates in the store with their status. |
| `reactor-ca host info <host-id>` | Display detailed information about a specific host certificate. |
| `reactor-ca host deploy <host-id|--all>` | Run the configured deployment command for one or all hosts. |
| `reactor-ca host export-key <host-id>` | Export the unencrypted private key for a host to a file or stdout. |
| `reactor-ca host import-key <host-id> --key <path>` | Import a pre-existing private key for a host. |
| `reactor-ca host sign-csr --csr <path> --out <path>` | Sign an external Certificate Signing Request (CSR). |
| `reactor-ca host clean` | Prune certificates/keys from the store for hosts no longer in `hosts.yaml`.|
| **Configuration Management** | |
| `reactor-ca config validate` | Validate the syntax and schema of `ca.yaml` and `hosts.yaml`. |

## 4. Functional Requirements

### 4.1. Initialization
-   **`reactor-ca init`**:
    -   Shall create a `config/` and `store/` directory.
    -   Shall populate `config/` with default `ca.yaml` and `hosts.yaml` example files.
    -   Shall create the necessary subdirectories within `store/` (`ca/`, `hosts/`).
    -   Shall not overwrite existing files unless a `--force` flag is used.

### 4.2. CA Management
-   **`reactor-ca ca create`**:
    -   Shall fail if a CA key/certificate already exists in the store.
    -   Shall generate a new private key according to `ca.yaml`.
    -   Shall generate a new self-signed root certificate.
    -   Shall write the encrypted private key and public certificate to the store.
-   **`reactor-ca ca renew`**:
    -   Shall load the existing CA private key.
    -   Shall generate a new self-signed certificate with a renewed validity period.
    -   Shall overwrite the existing `ca.crt` file in the store.
-   **`reactor-ca ca rekey`**:
    -   Similar to `create`, but intended to replace an existing CA.
    -   It will generate a new key and certificate, overwriting the old ones.
-   **`reactor-ca ca import`**:
    -   Shall read an external certificate and private key.
    -   Shall validate that the key and certificate match.
    -   Shall prompt for a new master password to encrypt the imported key.
    -   Shall write the certificate and the newly encrypted key to the store.
-   **`reactor-ca ca passwd`**:
    -   Shall prompt for the current master password.
    -   Shall prompt for a new master password (with confirmation).
    -   Shall decrypt every private key in the store (`ca` and `hosts`) and re-encrypt it with the new password.
    -   This must be an atomic operation; if any key fails, the process should be rolled back or the user clearly warned.

### 4.3. Host Certificate Management
-   **`reactor-ca host issue <host-id|--all>`**:
    -   Shall load CA key/cert and the host's configuration from `hosts.yaml`.
    -   If the host's key does not exist (or `--rekey` is used), generate a new private key based on the host's config.
    -   If the host's key exists, decrypt and use it.
    -   Shall generate a new certificate for the host, signed by the CA.
    -   Shall write the encrypted private key (if new) and certificate to the store.
    -   If configured, it shall export the certificate and/or chain to the specified file paths.
    -   If a `--deploy` flag is provided, it shall execute the deployment step after successful issuance and export.
-   **`reactor-ca host list`**:
    -   Shall display a table of all host certificates in the store.
    -   The table must include Host ID, Expiration Date, and Days Remaining.
    -   Days Remaining should be color-coded (e.g., red for expired/<30d, yellow for <90d).
    -   Shall support filters like `--expired` or `--expiring-in <days>`.
-   **`reactor-ca host deploy`**:
    -   Shall read the host's deployment configuration from `hosts.yaml`.
    -   The `command` string supports variable substitution:
        -   `${cert}`: Absolute path to the host's certificate file in the store.
        -   `${chain}`: Absolute path to a temporary file containing the host cert + CA cert.
        -   `${private_key}`: Absolute path to a temporary, unencrypted copy of the host's private key.
    -   The temporary key file must be created with secure permissions (0600) and reliably cleaned up after the command executes.
    -   The command must be executed in a way that prevents shell injection (i.e., not passed to a raw shell).
-   **`reactor-ca host sign-csr`**:
    -   Shall accept a path to a PEM-encoded CSR file.
    -   Shall validate the CSR's signature.
    -   Shall sign the CSR with the CA key, creating a new certificate.
    -   Shall write the resulting certificate to a specified output file or stdout.
    -   Certificate validity should be configurable via flags (e.g., `--days 365`).
-   **`reactor-ca host clean`**:
    -   Shall get a list of all hosts in `hosts.yaml`.
    -   Shall get a list of all host directories in `store/hosts/`.
    -   For any host directory that does not have a corresponding entry in `hosts.yaml`, it shall be deleted.
    -   A confirmation prompt should be displayed before deletion unless a `--force` flag is used.

### 4.4. Cryptography
-   **Key Algorithms:** Must support generating keys for:
    -   RSA (2048, 3072, 4096 bits)
    -   ECDSA (P-256, P-384, P-521)
    -   EdDSA (Ed25519, Ed448)
-   **Hash Algorithms:** Must support signing with:
    -   SHA-256, SHA-384, SHA-512
-   **Subject Alternative Names (SANs):** Must support adding SAN extensions for:
    -   DNS Names
    -   IP Addresses (IPv4 and IPv6)
    -   Email Addresses
    -   URIs

ALL write operations to the store must be logged to the ca.log file, including timestamps.

## 5. Configuration File Schema

### 5.1. `config/ca.yaml`
Defines the root CA.

```yaml
# config/ca.yaml
ca:
  # Subject details for the CA certificate
  common_name: "Reactor CA"
  organization: "Reactor Homelab"
  organization_unit: "IT Department"
  country: "US"
  state: "California"
  locality: "San Francisco"
  email: "ca-admin@reactor.dev"

  # Certificate validity
  validity:
    years: 10
    # or days: 3650

  # Cryptographic parameters
  key_algorithm: "ECP384" # RSA4096, ECP256, ED25519, etc.
  hash_algorithm: "SHA384" # SHA256, SHA512

  # Password settings
  password:
    min_length: 12
    file: "" # Optional: path to a file containing the master password
    env_var: "REACTOR_CA_PASSWORD" # Optional: env var for the password
```

### 5.2. `config/hosts.yaml`
A dictionary of all managed host certificates.

```yaml
# config/hosts.yaml
hosts:
  # A unique identifier for the host certificate
  web-server-prod:
    # Subject details (overrides CA defaults if present)
    common_name: "prod.reactor.dev"

    # Subject Alternative Names (SANs)
    alternative_names:
      dns:
        - "www.reactor.dev"
        - "api.reactor.dev"
      ip:
        - "10.0.0.10"
        - "2001:db8::10"

    # Certificate validity
    validity:
      days: 365

    # Cryptographic parameters
    key_algorithm: "RSA2048"
    hash_algorithm: "SHA256"

    # Export paths for certificate files
    export:
      cert: "/etc/ssl/certs/reactor.dev.pem"
      chain: "/etc/ssl/certs/reactor.dev.chain.pem"
      # Note: private key is not exported by default for security.

    # Command to run after successful certificate issuance and export
    deploy:
      command: "systemctl reload nginx"

  vpn-gateway:
    common_name: "vpn.reactor.dev"
    validity: { years: 1 }
    key_algorithm: "ED25519"
```

## 6. On-Disk Store Schema

The `store` directory is the single source of truth for all generated cryptographic assets.

```
store/
├── ca/
│   ├── ca.crt         # PEM-encoded CA public certificate
│   └── ca.key.enc     # PEM-encoded, encrypted (PKCS#8) CA private key
│
├── hosts/
│   ├── web-server-prod/
│   │   ├── cert.crt     # PEM-encoded host public certificate
│   │   └── cert.key.enc # PEM-encoded, encrypted host private key
│   │
│   └── vpn-gateway/
│       ├── cert.crt
│       └── cert.key.enc
│
└── ca.log                 # Log file for all operations
```

## 7. Non-Functional Requirements

-   **Security:**
    -   Keys at rest must always be encrypted.
    -   Temporary files containing sensitive data (like unencrypted keys for deployment) must use secure permissions and be reliably cleaned up.
    -   The application must not be vulnerable to command injection.
    -   Use constant-time operations where appropriate for cryptographic comparisons.
-   **Usability:**
    -   CLI commands and flags must be consistent and well-documented (`--help`).
    -   Error messages must be clear, specific, and actionable.
    -   JSON output should be available for programmatic use (e.g., `reactor-ca host list --json`).
-   **Portability:**
    -   The final product must be a single, statically-linked Go binary with no runtime dependencies.
    -   It must be tested and functional on Linux, macOS, and Windows.
-   **Testability:**
    -   The codebase must be structured into modular packages (e.g., `cli`, `store`, `crypto`, `config`).
    -   Core logic (crypto, store operations) must have extensive unit tests that do not rely on the actual filesystem.

## 8. Out of Scope

The following features will not be part of this implementation:
-   Certificate Revocation (CRLs and OCSP).
-   PKCS#12 bundle creation/export.
-   Automated certificate renewal (the tool provides the commands for automation, but does not include a scheduler/daemon).
-   A graphical user interface (GUI).

=== example_config/ca.yaml ===
# ReactorCA: Certificate Authority Configuration
# This file defines the properties of your root Certificate Authority.

ca:
  # --- Subject Details ---
  # These values are used to build the distinguished name (DN) of the CA certificate.
  common_name: "Reactor Homelab CA"
  organization: "Reactor Industries"
  organization_unit: "IT Department"
  country: "DE"                 # 2-letter country code
  state: "Berlin"               # State or province
  locality: "Berlin"            # City or locality
  email: "admin@reactor.dev"  # Administrative contact

  # --- Validity Period ---
  # How long the CA certificate will be valid for.
  # Specify exactly one of `years` or `days`.
  validity:
    years: 10
    # days: 3650

  # --- Cryptographic Settings ---
  # The algorithm used for the CA's private key.
  # Supported: RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519, ED448
  key_algorithm: "ECP384"

  # The hash algorithm used for the certificate signature.
  # Supported: SHA256, SHA384, SHA512
  hash_algorithm: "SHA384"

  # --- Password Management ---
  # Defines how the master password for encrypting private keys is handled.
  password:
    # Minimum required password length during interactive prompts.
    min_length: 12

    # Optional: Path to a file containing the master password.
    # If set, the CLI will not prompt for a password.
    # file: "/run/secrets/reactor_ca_password"

    # Optional: Name of the environment variable containing the master password.
    # This is checked if `file` is not set or does not exist.
    env_var: "REACTOR_CA_PASSWORD"

=== example_config/hosts.yaml ===
# ReactorCA: Host Certificate Configuration
# This file defines the certificates you want to issue for your hosts/services.

hosts:
  # This is a unique ID for the certificate, used in CLI commands (e.g., `reactor-ca host issue web-server`).
  web-server:
    # --- Subject Details ---
    # The Common Name (CN) is typically the primary fully-qualified domain name (FQDN).
    common_name: "web.reactor.local"

    # Other subject fields are optional and will inherit from ca.yaml if not specified.
    # organization_unit: "Web Services"

    # --- Subject Alternative Names (SANs) ---
    # A list of additional names the certificate should be valid for. This is highly recommended.
    alternative_names:
      dns:
        - "web.reactor.local"
        - "grafana.reactor.local"
        - "prometheus.reactor.local"
      ip:
        - "192.168.1.100"
        - "10.10.0.1"

    # --- Validity Period ---
    # How long the host certificate will be valid for.
    validity:
      years: 1
      # days: 365

    # --- Cryptographic Settings ---
    # Algorithm for this specific host's key.
    key_algorithm: "RSA2048"
    # Signing hash for this specific certificate.
    hash_algorithm: "SHA256"

    # --- Export & Deploy ---
    # Optional: Defines where to copy the certificate files after they are issued.
    export:
      # Path to save the host certificate (PEM format).
      cert: "./export/web-server/cert.pem"
      # Path to save the full chain (host certificate + CA certificate).
      chain: "./export/web-server/chain.pem"

    # Optional: A command to run after the certificate has been issued and exported.
    # Useful for reloading services that use the certificate.
    # Variables: ${cert}, ${chain}, ${private_key}
    deploy:
      command: "docker kill --signal=HUP my-reverse-proxy"
      # Example for a traditional server:
      # command: "cp ${chain} /etc/nginx/ssl/site.pem && cp ${private_key} /etc/nginx/ssl/site.key && systemctl reload nginx"

  vpn-gateway:
    common_name: "vpn.reactor.local"
    validity:
      years: 1
    key_algorithm: "ED25519"
    export:
      cert: "./export/vpn-gateway/cert.pem"
      chain: "./export/vpn-gateway/chain.pem"
    deploy:
      command: "systemctl restart wireguard-wg0"

---
Tokens: 47855 input, 4993 output, 55562 total
Cost: $0.059818 input + $0.049930 output = $0.109748 total
