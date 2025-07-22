you are a senior Go engineer with a lot of experience with encryption and security and a faible for CLI/text-based user interfaces/UX, especially X.509 PKI management. review the following home-lab/SOHO CLI CA implementation with regards to

- secure and future-proof (for at least 10 years) encryption defaults and internal parameters
- choice of security relevant external crypto/PKI libraries
- logic errors in the code
- UX flaws, for example missing or unclear error messages. we want to be helpful!
- test coverage

write missing tests if appropriate!

if you want to update/create files, mark output files with `=== $filename ===`, as we do in the input, and bundle them at the end of your response.

current implementation:

--- LLM Response ---
Excellent. This is a very solid foundation for a homelab CA tool. The code is well-structured using a clean architecture approach, which is commendable. The CLI design is logical, and the feature set is well-suited for the target audience.

I'll provide a detailed review based on the criteria you've laid out.

---

### Overall Assessment

This is a B+ to A- implementation. It gets most things right, especially in terms of architecture and basic functionality. The main areas for improvement are hardening the cryptographic defaults for long-term security, enhancing user feedback on errors, and improving robustness in a few key areas.

---

### 1. Secure and Future-Proof Encryption Defaults

The choices of algorithms are good, but the parameters for key derivation can and should be hardened to meet the "future-proof for 10 years" goal.

**Critique:**

*   **PBKDF2 Iteration Count:** In `internal/infra/crypto/service.go`, the `EncryptPrivateKey` function uses PBKDF2 with `IterationCount: 100000`. This was acceptable several years ago, but for a new tool aiming for 10 years of security, it's too low. Brute-force capabilities improve constantly. OWASP currently recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256.
*   **PBKDF2 Hash Function:** The KDF uses `crypto.SHA256`. While secure, using `crypto.SHA512` is slightly more robust against future attacks on the SHA-2 family and is a better match for a high-security context.

**Recommendation:**

I will update `internal/infra/crypto/service.go` to significantly increase the iteration count and use a stronger hash for the KDF. This has a minor performance impact on key decryption, but for a CLI tool used infrequently, security should be prioritized over a few hundred milliseconds of wait time.

*   Increase `IterationCount` from `100000` to `600000`.
*   Change `HMACHash` from `crypto.SHA256` to `crypto.SHA512`.

### 2. Choice of Security Relevant Libraries

**Critique:**

*   **`github.com/youmark/pkcs8`**: This is a good choice. The Go standard library makes encrypting private keys to the PKCS#8 standard surprisingly cumbersome. This library is a well-known, focused solution that wraps the standard crypto packages correctly. No issues here, provided we use it with strong parameters (as addressed above).
*   **Standard Libraries**: The use of `crypto/*`, `crypto/x509`, and `golang.org/x/crypto` is perfect. Relying on the standard library for core cryptographic primitives is always the right call.

**Recommendation:**

No changes needed. The library choices are sound.

### 3. Logic Errors & Robustness

The logic is generally solid, but there are a few areas that could be improved for robustness and clarity.

**Critique:**

*   **Mismatched `deploy` Logic:** The `README.md` and the `DeployConfig` struct (`command` vs `commands`) suggest a confusing configuration story. The documentation claims complex shell syntax isn't supported, but the implementation in `internal/app/application.go` uses `bash -c`, which absolutely supports it. This can lead to user confusion and unexpected behavior.
*   **Non-Atomic Password Change:** The `ChangePassword` function in `application.go` decrypts all keys, then re-encrypts and overwrites them one by one. If the program is interrupted (e.g., Ctrl+C, power loss) during the write phase, the key store could be left in a corrupt, partially-updated state.
*   **Deploy Command Variable Substitution:** The `DeployHost` function uses `strings.NewReplacer` with variables like `${cert}`. However, the path it substitutes for `${cert}` is the one in the `store/`, not the one from the `export:` block in the config. A user would likely expect the variable to point to the file they configured for export.

**Recommendation:**

1.  **Simplify `deploy` configuration:** I will update the configuration schema to *only* use `commands: []string`. This is more explicit and flexible. The single `command` field will be removed. This requires changes in `domain/config.go`, `config/yaml_loader.go` (for validation), `cmd/reactor-ca/commands/init.go` (for the default config), and the `README.md`.
2.  **Improve `DeployHost` variable substitution:** The `${cert}` and `${chain}` variables should point to the paths defined in the `export` block of `hosts.yaml` if they exist. If not, they can fall back to temporary files. The `${private_key}` must always be a temporary file for security.
3.  **Improve `ChangePassword` robustness:** The ideal solution involves a two-phase commit (write to temp files, then rename), which is complex. A simpler, significant improvement is to create a single backup of the entire `store/` directory before starting the operation. I will add this logic to `ChangePassword`.

### 4. UX Flaws & Error Messages

The UX is quite good, but we can make it even more helpful.

**Critique:**

*   **Generic Decryption Error:** When a user enters the wrong password, the error is `failed to decrypt...`. We can detect this specific case and give a much clearer message: "Incorrect password."
*   **Confusing `deploy` config:** As mentioned in the logic section, this is also a UX flaw.
*   **`init` command YAML:** The default YAML in `init.go` uses `subject:` sub-keys, which is a good, structured approach. The `README.md` examples should be updated to match this superior structure.

**Recommendation:**

1.  **Improve Password Error:** I will modify `DecryptPrivateKey` in the crypto service to check for the specific incorrect password error from the underlying library and wrap it in a custom error type. The application layer can then catch this and show a user-friendly message.
2.  **Update `README.md` and `init.go`:** I will align all configuration examples and templates to use the cleaner, more consistent structure I'm proposing.
3.  **Enhance `ca rekey` Warning:** The prompt is good, but I'll add more color and detail to emphasize the danger of the operation and what it implies (all previously issued certs will need to be re-issued).

### 5. Test Coverage

The end-to-end integration test (`main_test.go`) is excellent. It validates the most critical workflow against the real binary and even cross-checks with `openssl`.

**Critique:**

*   **Lack of Unit Tests:** The project has zero unit tests. The clean architecture makes unit testing the `internal` packages very feasible and valuable. Logic inside the `app` and `infra` layers should be tested in isolation.
*   **Missing Failure Case Tests:** The integration test covers the happy path well but lacks tests for predictable failures (e.g., trying to create a CA that already exists, using the wrong password, providing invalid config).

**Recommendation:**

I will write a new unit test file, **`internal/app/application_test.go`**, to demonstrate how to test the application logic using mock dependencies. This will test the `CleanHosts` and `DeployHost` use cases, which have interesting logic worth testing in isolation. This serves as a template for how other parts of the application can be unit-tested.

---

### Proposed Changes

I will now provide the updated and new files that implement the recommendations above.

=== README.md ===
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

=== cmd/reactor-ca/commands/ca.go ===
package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.dev/reactor-ca/internal/domain"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the Certificate Authority",
}

// ca create
var caCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new CA key and self-signed certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.CreateCA(cmd.Context())
		if err != nil {
			if err == domain.ErrCAAlreadyExists {
				return fmt.Errorf("%w\n%s", err, "Hint: To replace the existing CA, use 'reactor-ca ca rekey'.")
			}
			return err
		}
		fmt.Println("✅ CA created successfully.")
		return nil
	},
}

// ca renew
var caRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew the CA certificate using the existing key",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.RenewCA(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println("✅ CA renewed successfully.")
		return nil
	},
}

// ca rekey
var caRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Create a new key and a new self-signed certificate, retiring the old ones",
	Long: strings.TrimSpace(`
Create a new key and a new self-signed certificate, retiring the old ones.

WARNING: This is a destructive operation.
The old CA key will be gone forever. All certificates previously issued by the old CA
will no longer be trusted by clients that trust the new CA. You will need to
re-issue and re-deploy all host certificates after this operation.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			yellow := color.New(color.FgYellow).SprintFunc()
			red := color.New(color.FgRed).SprintFunc()

			fmt.Println(yellow("You are about to perform a CA re-key operation."))
			fmt.Println(yellow("This will generate a new private key and certificate for your root CA."))
			fmt.Println(red("This action is irreversible and will invalidate all previously issued certificates."))
			fmt.Println(red("You must re-issue and deploy all host certificates afterwards."))
		}

		err := appCtx.App.RekeyCA(cmd.Context(), force)
		if err != nil {
			return err
		}
		color.Green("✅ CA re-keyed successfully. Remember to re-issue all host certificates.")
		return nil
	},
}

// ca info
var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display detailed information about the CA certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		info, err := appCtx.App.InfoCA(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println(info)
		return nil
	},
}

// ca import
var (
	importCertPath string
	importKeyPath  string
)
var caImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an existing CA certificate and private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ImportCA(cmd.Context(), importCertPath, importKeyPath)
		if err != nil {
			return err
		}
		fmt.Println("✅ CA imported successfully.")
		return nil
	},
}

// ca passwd
var caPasswdCmd = &cobra.Command{
	Use:   "passwd",
	Short: "Change the master password for all encrypted keys in the store",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ChangePassword(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println("✅ Master password changed successfully for all keys.")
		return nil
	},
}

func init() {
	caImportCmd.Flags().StringVar(&importCertPath, "cert", "", "Path to the CA certificate file (PEM format)")
	caImportCmd.Flags().StringVar(&importKeyPath, "key", "", "Path to the CA private key file (PEM format)")
	_ = caImportCmd.MarkFlagRequired("cert")
	_ = caImportCmd.MarkFlagRequired("key")

	caRekeyCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	caCmd.AddCommand(caCreateCmd)
	caCmd.AddCommand(caRenewCmd)
	caCmd.AddCommand(caRekeyCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caImportCmd)
	caCmd.AddCommand(caPasswdCmd)
}

=== cmd/reactor-ca/commands/init.go ===
package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var forceInit bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize config and store directories",
	Long:  `Creates the necessary directory structure (config/, store/) and populates it with default configuration files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootPath, err := cmd.Flags().GetString("root")
		if err != nil {
			return err
		}
		if rootPath == "" {
			rootPath = os.Getenv("REACTOR_CA_ROOT")
		}
		if rootPath == "" {
			rootPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("could not determine current directory: %w", err)
			}
		}

		fmt.Printf("Initializing Reactor CA in %s...\n", rootPath)

		dirs := []string{
			filepath.Join(rootPath, "config"),
			filepath.Join(rootPath, "store"),
			filepath.Join(rootPath, "store", "ca"),
			filepath.Join(rootPath, "store", "hosts"),
		}

		for _, dir := range dirs {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
			fmt.Printf("✓ Created directory: %s\n", dir)
		}

		files := map[string]string{
			filepath.Join(rootPath, "config", "ca.yaml"):    defaultCaYAML,
			filepath.Join(rootPath, "config", "hosts.yaml"): defaultHostsYAML,
		}

		for path, content := range files {
			if _, err := os.Stat(path); err == nil && !forceInit {
				fmt.Printf("! Skipping existing file: %s (use --force to overwrite)\n", path)
				continue
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write file %s: %w", path, err)
			}
			fmt.Printf("✓ Created config file: %s\n", path)
		}

		fmt.Println("\nInitialization complete. Review the files in config/ and then run 'reactor-ca ca create'.")
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Overwrite existing configuration files")
}

const defaultCaYAML = `# ReactorCA: Certificate Authority Configuration
# This file defines the properties of your root Certificate Authority.

ca:
  # --- Subject Details ---
  # These values are used to build the distinguished name (DN) of the CA certificate.
  subject:
    common_name: "Reactor Homelab CA"
    organization: "Reactor Industries"
    organization_unit: "IT Department"
    country: "DE"                 # 2-letter country code
    state: "Berlin"               # State or province
    locality: "Berlin"            # City or locality
    email: "admin@reactor.dev"  # Administrative contact

  # --- Validity Period ---
  # How long the CA certificate will be valid for.
  # Specify exactly one of 'years' or 'days'.
  validity:
    years: 10
    # days: 3650

  # --- Cryptographic Settings ---
  # The algorithm used for the CA's private key.
  # Supported: RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519
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
    # This is checked if 'file' is not set or does not exist.
    env_var: "REACTOR_CA_PASSWORD"
`

const defaultHostsYAML = `# ReactorCA: Host Certificate Configuration
# This file defines the certificates you want to issue for your hosts/services.

hosts:
  # This is a unique ID for the certificate, used in CLI commands (e.g., 'reactor-ca host issue web-server').
  web-server-example:
    # --- Subject Details ---
    # The Common Name (CN) is typically the primary fully-qualified domain name (FQDN).
    subject:
      common_name: "web.reactor.local"
      # Other subject fields are optional and will inherit from ca.yaml if not specified.
      # organization_unit: "Web Services"

    # --- Subject Alternative Names (SANs) ---
    # A list of additional names the certificate should be valid for. This is highly recommended.
    alternative_names:
      dns:
        - "web.reactor.local"
        - "grafana.reactor.local"
      ip:
        - "192.168.1.100"
        - "10.10.0.1"

    # --- Validity Period ---
    # How long the host certificate will be valid for.
    validity:
      years: 1
      # days: 365

    # --- Cryptographic Settings ---
    # Algorithm for this specific host's key. Defaults to CA's key_algorithm if unset.
    key_algorithm: "RSA2048"
    # Signing hash for this specific certificate. Defaults to CA's hash_algorithm if unset.
    hash_algorithm: "SHA256"

    # --- Export & Deploy ---
    # Optional: Defines where to copy the certificate files after they are issued.
    # The parent directory will be created if it doesn't exist.
    export:
      # Path to save the host certificate (PEM format).
      cert: "/tmp/reactor-ca/exports/web-server/cert.pem"
      # Path to save the full chain (host certificate + CA certificate).
      chain: "/tmp/reactor-ca/exports/web-server/chain.pem"

    # Optional: A list of commands to run after the certificate has been issued and exported.
    # These are executed as a shell script using 'bash -c'.
    # Variables:
    # - ${cert}: Absolute path to the exported certificate file.
    # - ${chain}: Absolute path to the exported chain file.
    # - ${private_key}: Absolute path to a temporary, unencrypted private key file.
    #   This file is created with secure permissions and is automatically deleted after the script runs.
    deploy:
      commands:
        # - "scp ${chain} ${cert} user@host:/etc/ssl/certs/"
        # - "ssh user@host -- 'systemctl reload nginx'"
        - "echo 'Deployment for web-server-example would run now.'"
        - "echo 'Cert Path: ${cert}'"
        - "echo 'Key Path: ${private_key}'"
`

=== internal/app/application.go ===
package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reactor.dev/reactor-ca/internal/domain"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath         string
	logger           domain.Logger
	configLoader     domain.ConfigLoader
	store            domain.Store
	cryptoSvc        domain.CryptoService
	passwordProvider domain.PasswordProvider
	commander        domain.Commander
}

// NewApplication creates a new Application instance.
func NewApplication(
	rootPath string,
	logger domain.Logger,
	configLoader domain.ConfigLoader,
	store domain.Store,
	cryptoSvc domain.CryptoService,
	passwordProvider domain.PasswordProvider,
	commander domain.Commander,
) *Application {
	return &Application{
		rootPath:         rootPath,
		logger:           logger,
		configLoader:     configLoader,
		store:            store,
		cryptoSvc:        cryptoSvc,
		passwordProvider: passwordProvider,
		commander:        commander,
	}
}

// ValidateConfig checks if the configuration files are valid.
func (a *Application) ValidateConfig(ctx context.Context) error {
	a.logger.Log("Validating configuration files...")
	if _, err := a.configLoader.LoadCA(); err != nil {
		return fmt.Errorf("invalid ca.yaml: %w", err)
	}
	if _, err := a.configLoader.LoadHosts(); err != nil {
		return fmt.Errorf("invalid hosts.yaml: %w", err)
	}

	a.logger.Log("Configuration files are valid.")
	return nil
}

// CreateCA creates a new Certificate Authority.
func (a *Application) CreateCA(ctx context.Context) error {
	return a.createCA(ctx, false)
}

// createCA creates a new Certificate Authority with optional force parameter.
func (a *Application) createCA(ctx context.Context, force bool) error {
	if !force {
		exists, err := a.store.CAExists()
		if err != nil {
			return fmt.Errorf("could not check for existing CA: %w", err)
		}
		if exists {
			return domain.ErrCAAlreadyExists
		}
	}

	a.logger.Log("Loading CA configuration...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	a.logger.Log(fmt.Sprintf("Generating private key with algorithm %s...", cfg.CA.KeyAlgorithm))
	key, err := a.cryptoSvc.GeneratePrivateKey(cfg.CA.KeyAlgorithm)
	if err != nil {
		return err
	}

	a.logger.Log("Creating self-signed root certificate...")
	cert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}

	a.logger.Log("Encrypting private key...")
	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	a.logger.Log("Saving CA certificate and encrypted key to store...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(cert)
	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}

	a.logger.Log("CA created successfully.")
	return nil
}

// RenewCA renews the CA certificate using the existing key.
func (a *Application) RenewCA(ctx context.Context) error {
	a.logger.Log("Renewing CA certificate...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Loading existing CA key...")
	encryptedKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetMasterPassword(ctx, cfg.CA.Password)
	if err != nil {
		return err
	}

	key, err := a.cryptoSvc.DecryptPrivateKey(encryptedKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err // Return the specific error for better UX
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	a.logger.Log("Creating new self-signed root certificate...")
	newCert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}

	a.logger.Log("Saving renewed CA certificate...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(newCert)
	// We only need to save the cert, as the key is unchanged.
	if err := a.store.SaveCA(certPEM, nil); err != nil {
		return err
	}

	a.logger.Log("CA renewed successfully.")
	return nil
}

// RekeyCA creates a new key and certificate, replacing the old ones.
func (a *Application) RekeyCA(ctx context.Context, force bool) error {
	a.logger.Log("Re-keying CA. This will replace the existing CA key and certificate.")
	if !force {
		confirmed, err := a.passwordProvider.Confirm("Are you sure you want to proceed? [y/N]: ")
		if err != nil {
			return err
		}
		if !confirmed {
			return domain.ErrActionAborted
		}
	}
	// Create new CA, allowing overwrite of existing CA
	return a.createCA(ctx, true)
}

// InfoCA returns a formatted string with details about the CA certificate.
func (a *Application) InfoCA(ctx context.Context) (string, error) {
	a.logger.Log("Loading CA certificate info...")
	cert, err := a.store.LoadCACert()
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ImportCA imports an existing CA from external files.
func (a *Application) ImportCA(ctx context.Context, certPath, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing CA from cert: %s, key: %s", certPath, keyPath))

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := a.cryptoSvc.ParseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	if err := a.cryptoSvc.ValidateKeyPair(cert, key); err != nil {
		return err
	}

	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetPasswordForImport(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log("CA imported successfully.")
	return nil
}

// ChangePassword re-encrypts all keys in the store with a new password.
func (a *Application) ChangePassword(ctx context.Context) error {
	a.logger.Log("Starting password change process...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Create a backup before proceeding
	backupPath, err := a.backupStore("passwd-change")
	if err != nil {
		return fmt.Errorf("failed to create store backup before password change: %w", err)
	}
	a.logger.Log(fmt.Sprintf("Created a backup of the store at: %s", backupPath))
	fmt.Printf("A backup of your store has been created at %s\n", backupPath)

	fmt.Println("Enter current master password:")
	oldPassword, err := a.passwordProvider.GetMasterPassword(ctx, cfg.CA.Password)
	if err != nil {
		return err
	}

	fmt.Println("Enter new master password:")
	newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return fmt.Errorf("failed to list keys in store: %w", err)
	}

	type reEncryptedKey struct {
		path string
		key  []byte
	}
	reEncryptedKeys := make([]reEncryptedKey, 0, len(keyPaths))

	a.logger.Log(fmt.Sprintf("Decrypting %d keys with old password...", len(keyPaths)))
	for _, path := range keyPaths {
		encryptedPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key %s: %w", path, err)
		}
		key, err := a.cryptoSvc.DecryptPrivateKey(encryptedPEM, oldPassword)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return fmt.Errorf("%w for key %s. Aborting. No changes have been made", err, filepath.Base(path))
			}
			return fmt.Errorf("failed to decrypt key %s: %w. Aborting password change", filepath.Base(path), err)
		}

		reEncrypted, err := a.cryptoSvc.EncryptPrivateKey(key, newPassword)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt key %s: %w", path, err)
		}

		reEncryptedKeys = append(reEncryptedKeys, reEncryptedKey{path: path, key: reEncrypted})
	}

	a.logger.Log("All keys decrypted successfully. Writing re-encrypted keys back to store...")
	for _, item := range reEncryptedKeys {
		if err := a.store.UpdateEncryptedKey(item.path, item.key); err != nil {
			return fmt.Errorf("FATAL: failed to write re-encrypted key %s. Your keys may be in an inconsistent state. PLEASE RESTORE FROM THE BACKUP. Error: %w", item.path, err)
		}
	}

	a.logger.Log("Password change complete. Backup can be removed if everything is working.")
	return nil
}

// GetAllHostIDs returns a list of all host IDs from the configuration.
func (a *Application) GetAllHostIDs(ctx context.Context) ([]string, error) {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hostsCfg.Hosts))
	for id := range hostsCfg.Hosts {
		ids = append(ids, id)
	}
	return ids, nil
}

// IssueHost creates or renews a certificate for a single host.
func (a *Application) IssueHost(ctx context.Context, hostID string, rekey, shouldDeploy bool) error {
	a.logger.Log(fmt.Sprintf("Starting certificate issuance for host '%s'", hostID))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return err
	}

	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}

	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	var hostKey crypto.Signer
	keyExists, err := a.store.HostKeyExists(hostID)
	if err != nil {
		return err
	}
	if rekey || !keyExists {
		if rekey {
			a.logger.Log(fmt.Sprintf("Rekey requested for '%s'. Generating new key.", hostID))
		} else {
			a.logger.Log(fmt.Sprintf("No key found for '%s'. Generating new key.", hostID))
		}
		algo := hostCfg.KeyAlgorithm
		if algo == "" {
			algo = caCfg.CA.KeyAlgorithm
		}
		hostKey, err = a.cryptoSvc.GeneratePrivateKey(algo)
		if err != nil {
			return err
		}
		encryptedHostKey, err := a.cryptoSvc.EncryptPrivateKey(hostKey, password)
		if err != nil {
			return err
		}
		if err := a.store.SaveHostKey(hostID, encryptedHostKey); err != nil {
			return err
		}
	} else {
		a.logger.Log(fmt.Sprintf("Using existing key for '%s'.", hostID))
		hostKeyData, err := a.store.LoadHostKey(hostID)
		if err != nil {
			return err
		}
		hostKey, err = a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return err
			}
			return fmt.Errorf("failed to decrypt host key: %w", err)
		}
	}

	a.logger.Log(fmt.Sprintf("Creating certificate for '%s'...", hostID))
	hostCert, err := a.cryptoSvc.CreateHostCertificate(&hostCfg, caCert, caKey, hostKey.Public())
	if err != nil {
		return err
	}
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
	if err := a.store.SaveHostCert(hostID, certPEM); err != nil {
		return err
	}

	if err := a.exportHostFiles(hostID, hostCert, caCert); err != nil {
		return err
	}

	if shouldDeploy {
		a.logger.Log(fmt.Sprintf("Deployment requested for '%s'.", hostID))
		if err := a.DeployHost(ctx, hostID); err != nil {
			return fmt.Errorf("deployment failed: %w", err)
		}
	}
	a.logger.Log(fmt.Sprintf("Successfully issued certificate for '%s'", hostID))
	return nil
}

func (a *Application) exportHostFiles(hostID string, hostCert, caCert *x509.Certificate) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg := hostsCfg.Hosts[hostID]

	// Export certificate
	if hostCfg.Export.Cert != "" {
		certPath := a.resolvePath(hostCfg.Export.Cert)
		a.logger.Log(fmt.Sprintf("Exporting certificate to %s", certPath))
		if err := a.writeFileWithDir(certPath, a.cryptoSvc.EncodeCertificateToPEM(hostCert), 0644); err != nil {
			return fmt.Errorf("failed to export certificate: %w", err)
		}
	}

	// Export chain
	if hostCfg.Export.Chain != "" {
		chainPath := a.resolvePath(hostCfg.Export.Chain)
		a.logger.Log(fmt.Sprintf("Exporting certificate chain to %s", chainPath))
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		caCertPEM := a.cryptoSvc.EncodeCertificateToPEM(caCert)
		chain := bytes.Join([][]byte{hostCertPEM, caCertPEM}, []byte{})
		if err := a.writeFileWithDir(chainPath, chain, 0644); err != nil {
			return fmt.Errorf("failed to export chain: %w", err)
		}
	}
	return nil
}

// DeployHost runs the deployment command for a host.
func (a *Application) DeployHost(ctx context.Context, hostID string) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	if len(hostCfg.Deploy.Commands) == 0 {
		return domain.ErrNoDeployCommand
	}
	a.logger.Log(fmt.Sprintf("Running %d deploy command(s) for '%s'", len(hostCfg.Deploy.Commands), hostID))

	// Get unencrypted key
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return err
	}
	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(hostKey)
	if err != nil {
		return err
	}

	// Create temp file for key
	tempKeyFile, err := os.CreateTemp("", "reactor-ca-key-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temp key file: %w", err)
	}
	defer os.Remove(tempKeyFile.Name())
	if err := os.Chmod(tempKeyFile.Name(), 0600); err != nil {
		return fmt.Errorf("failed to set permissions on temp key file: %w", err)
	}
	if _, err := tempKeyFile.Write(keyPEM); err != nil {
		return fmt.Errorf("failed to write to temp key file: %w", err)
	}
	if err := tempKeyFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp key file: %w", err)
	}

	// Variable substitution
	certPath := a.resolvePath(hostCfg.Export.Cert)
	chainPath := a.resolvePath(hostCfg.Export.Chain)

	// If export paths are not defined, we must create temporary files for them too.
	if certPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		tempCertFile, err := os.CreateTemp("", "reactor-ca-cert-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp cert file: %w", err)
		}
		defer os.Remove(tempCertFile.Name())
		if _, err := tempCertFile.Write(hostCertPEM); err != nil {
			return fmt.Errorf("failed to write to temp cert file: %w", err)
		}
		if err := tempCertFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp cert file: %w", err)
		}
		certPath = tempCertFile.Name()
	}
	if chainPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		caCert, err := a.store.LoadCACert()
		if err != nil {
			return err
		}
		chainPEM := bytes.Join([][]byte{
			a.cryptoSvc.EncodeCertificateToPEM(hostCert),
			a.cryptoSvc.EncodeCertificateToPEM(caCert),
		}, []byte{})

		tempChainFile, err := os.CreateTemp("", "reactor-ca-chain-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp chain file: %w", err)
		}
		defer os.Remove(tempChainFile.Name())
		if _, err := tempChainFile.Write(chainPEM); err != nil {
			return fmt.Errorf("failed to write to temp chain file: %w", err)
		}
		if err := tempChainFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp chain file: %w", err)
		}
		chainPath = tempChainFile.Name()
	}

	replacer := strings.NewReplacer(
		"${cert}", certPath,
		"${chain}", chainPath,
		"${private_key}", tempKeyFile.Name(),
	)

	var substitutedCommands []string
	for _, cmd := range hostCfg.Deploy.Commands {
		substitutedCommands = append(substitutedCommands, replacer.Replace(cmd))
	}

	// Create shell script with safety flags
	shellScript := "set -euo pipefail\n" + strings.Join(substitutedCommands, "\n")

	// Execute via shell
	a.logger.Log(fmt.Sprintf("Executing deploy script for '%s':\n%s", hostID, shellScript))
	output, err := a.commander.Execute("bash", "-c", shellScript)
	if err != nil {
		return fmt.Errorf("deploy command failed: %w\nOutput:\n%s", err, string(output))
	}
	a.logger.Log(fmt.Sprintf("Deploy commands for '%s' successful. Output: %s", hostID, string(output)))
	return nil
}

// ListHosts returns information about all host certificates in the store.
func (a *Application) ListHosts(ctx context.Context) ([]*domain.HostInfo, error) {
	a.logger.Log("Listing hosts from store...")
	hostIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}
	infoList := make([]*domain.HostInfo, 0, len(hostIDs))
	for _, id := range hostIDs {
		cert, err := a.store.LoadHostCert(id)
		if err != nil {
			a.logger.Error(fmt.Sprintf("Could not load certificate for host '%s', skipping: %v", id, err))
			continue
		}
		daysRemaining := int64(time.Until(cert.NotAfter).Hours() / 24)
		infoList = append(infoList, &domain.HostInfo{
			ID:            id,
			CommonName:    cert.Subject.CommonName,
			NotAfter:      cert.NotAfter,
			DaysRemaining: daysRemaining,
		})
	}
	return infoList, nil
}

// InfoHost returns details for a specific host certificate.
func (a *Application) InfoHost(ctx context.Context, hostID string) (string, error) {
	a.logger.Log(fmt.Sprintf("Loading host certificate info for '%s'...", hostID))
	cert, err := a.store.LoadHostCert(hostID)
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ExportHostKey returns the unencrypted private key for a host.
func (a *Application) ExportHostKey(ctx context.Context, hostID string) ([]byte, error) {
	a.logger.Log(fmt.Sprintf("Exporting private key for host '%s'", hostID))
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return nil, err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return nil, err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return nil, err
	}
	return a.cryptoSvc.EncodeKeyToPEM(hostKey)
}

// ExportHostKeyToFile exports the unencrypted private key for a host to a file.
func (a *Application) ExportHostKeyToFile(ctx context.Context, hostID, outputPath string) error {
	keyPEM, err := a.ExportHostKey(ctx, hostID)
	if err != nil {
		return err
	}

	resolvedPath := a.resolvePath(outputPath)
	if err := os.WriteFile(resolvedPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key to %s: %w", resolvedPath, err)
	}
	a.logger.Log(fmt.Sprintf("Exported unencrypted key for '%s' to %s", hostID, resolvedPath))
	return nil
}

// ImportHostKey imports an external key for a host.
func (a *Application) ImportHostKey(ctx context.Context, hostID, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing key for host '%s' from %s", hostID, keyPath))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	if _, ok := hostsCfg.Hosts[hostID]; !ok {
		return domain.ErrHostNotFoundInConfig
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	if err := a.store.SaveHostKey(hostID, encryptedKey); err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Key for host '%s' imported successfully.", hostID))
	return nil
}

// SignCSR signs an external Certificate Signing Request.
func (a *Application) SignCSR(ctx context.Context, csrPath string, validityDays int) ([]byte, error) {
	a.logger.Log(fmt.Sprintf("Signing CSR from %s", csrPath))
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSR file: %w", err)
	}
	csr, err := a.cryptoSvc.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return nil, err
	}
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return nil, err
	}
	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return nil, err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		return nil, err
	}

	cert, err := a.cryptoSvc.SignCSR(csr, caCert, caKey, validityDays)
	if err != nil {
		return nil, err
	}

	a.logger.Log("CSR signed successfully.")
	return a.cryptoSvc.EncodeCertificateToPEM(cert), nil
}

// CleanHosts removes hosts from the store that are no longer in the config.
func (a *Application) CleanHosts(ctx context.Context, force bool) ([]string, error) {
	a.logger.Log("Checking for hosts to clean from the store...")
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	storeIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}

	configIDs := make(map[string]struct{})
	for id := range hostsCfg.Hosts {
		configIDs[id] = struct{}{}
	}

	var toPrune []string
	for _, id := range storeIDs {
		if _, ok := configIDs[id]; !ok {
			toPrune = append(toPrune, id)
		}
	}

	if len(toPrune) == 0 {
		return nil, nil
	}

	fmt.Println("The following hosts exist in the store but not in hosts.yaml:")
	for _, id := range toPrune {
		fmt.Printf("- %s\n", id)
	}

	if !force {
		confirmed, err := a.passwordProvider.Confirm("Do you want to permanently delete these hosts from the store? [y/N]: ")
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return nil, domain.ErrActionAborted
		}
	}

	for _, id := range toPrune {
		a.logger.Log(fmt.Sprintf("Deleting host '%s' from store...", id))
		if err := a.store.DeleteHost(id); err != nil {
			a.logger.Error(fmt.Sprintf("Failed to delete host '%s': %v", id, err))
			// Continue to next host
		}
	}
	a.logger.Log("Host cleaning complete.")
	return toPrune, nil
}

func (a *Application) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(a.rootPath, path)
}

func (a *Application) writeFileWithDir(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func (a *Application) backupStore(reason string) (string, error) {
	storeDir := filepath.Join(a.rootPath, "store")
	backupFileName := fmt.Sprintf("store-backup-%s-%s.zip", time.Now().UTC().Format("20060102150405"), reason)
	backupFilePath := filepath.Join(a.rootPath, backupFileName)

	backupFile, err := os.Create(backupFilePath)
	if err != nil {
		return "", err
	}
	defer backupFile.Close()

	zipWriter := zip.NewWriter(backupFile)
	defer zipWriter.Close()

	err = filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(storeDir, path)
		if err != nil {
			return err
		}
		zipFile, err := zipWriter.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()
		_, err = io.Copy(zipFile, fsFile)
		return err
	})

	return backupFilePath, err
}

=== internal/domain/config.go ===
package domain

import "time"

// CAConfig holds the configuration for the root CA.
type CAConfig struct {
	CA struct {
		Subject       SubjectConfig  `yaml:"subject"`
		Validity      Validity       `yaml:"validity"`
		KeyAlgorithm  KeyAlgorithm   `yaml:"key_algorithm"`
		HashAlgorithm HashAlgorithm  `yaml:"hash_algorithm"`
		Password      PasswordConfig `yaml:"password"`
	} `yaml:"ca"`
}

// HostsConfig holds the configuration for all managed hosts.
type HostsConfig struct {
	Hosts map[string]HostConfig `yaml:"hosts"`
}

// HostConfig holds the configuration for a single host certificate.
type HostConfig struct {
	Subject          SubjectConfig `yaml:"subject"`
	AlternativeNames SANs          `yaml:"alternative_names"`
	Validity         Validity      `yaml:"validity"`
	KeyAlgorithm     KeyAlgorithm  `yaml:"key_algorithm"`
	HashAlgorithm    HashAlgorithm `yaml:"hash_algorithm"`
	Export           ExportConfig  `yaml:"export"`
	Deploy           DeployConfig  `yaml:"deploy"`
}

// SubjectConfig defines the fields for a certificate's subject.
type SubjectConfig struct {
	CommonName       string `yaml:"common_name"`
	Organization     string `yaml:"organization"`
	OrganizationUnit string `yaml:"organization_unit"`
	Country          string `yaml:"country"`
	State            string `yaml:"state"`
	Locality         string `yaml:"locality"`
	Email            string `yaml:"email"`
}

// Validity defines the duration for which a certificate is valid.
type Validity struct {
	Years int `yaml:"years"`
	Days  int `yaml:"days"`
}

func (v Validity) ToDuration() time.Duration {
	return time.Duration(v.Years)*365*24*time.Hour + time.Duration(v.Days)*24*time.Hour
}

// PasswordConfig defines how the master password is managed.
type PasswordConfig struct {
	MinLength int    `yaml:"min_length"`
	File      string `yaml:"file"`
	EnvVar    string `yaml:"env_var"`
}

// SANs holds the Subject Alternative Names.
type SANs struct {
	DNS   []string `yaml:"dns"`
	IP    []string `yaml:"ip"`
	Email []string `yaml:"email"`
	URI   []string `yaml:"uri"`
}

// ExportConfig defines paths for exporting generated files.
type ExportConfig struct {
	Cert  string `yaml:"cert"`
	Chain string `yaml:"chain"`
}

// DeployConfig defines the command(s) to run after issuance.
type DeployConfig struct {
	Commands []string `yaml:"commands"`
}

=== internal/domain/errors.go ===
package domain

import "errors"

var (
	ErrCAAlreadyExists      = errors.New("CA already exists in the store")
	ErrCANotFound           = errors.New("CA not found in the store. Run 'ca create' first")
	ErrHostNotFoundInConfig = errors.New("host not found in hosts.yaml configuration")
	ErrHostNotFoundInStore  = errors.New("host certificate or key not found in store")
	ErrHostKeyNotFound      = errors.New("host key not found in store")
	ErrHostCertNotFound     = errors.New("host certificate not found in store")
	ErrKeyCertMismatch      = errors.New("private key does not match public key in certificate")
	ErrValidation           = errors.New("configuration validation failed")
	ErrActionAborted        = errors.New("action aborted by user")
	ErrNoDeployCommand      = errors.New("no deploy command configured for this host")
	ErrIncorrectPassword    = errors.New("incorrect password")
)

=== internal/infra/config/yaml_loader.go ===
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
	"reactor.dev/reactor-ca/internal/domain"
)

// YAMLConfigLoader implements the domain.ConfigLoader interface for YAML files.
type YAMLConfigLoader struct {
	configPath string
}

// NewYAMLConfigLoader creates a new config loader.
func NewYAMLConfigLoader(configPath string) *YAMLConfigLoader {
	return &YAMLConfigLoader{configPath: configPath}
}

// LoadCA loads the CA configuration from ca.yaml.
func (l *YAMLConfigLoader) LoadCA() (*domain.CAConfig, error) {
	path := filepath.Join(l.configPath, "ca.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ca.yaml: %w", err)
	}

	var cfg domain.CAConfig
	// Use a decoder to get strict unmarshalling
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse ca.yaml: %w", err)
	}

	// Manual validation
	if cfg.CA.Subject.CommonName == "" {
		return nil, fmt.Errorf("%w: ca.subject.common_name is required in ca.yaml", domain.ErrValidation)
	}
	if cfg.CA.Validity.Years == 0 && cfg.CA.Validity.Days == 0 {
		return nil, fmt.Errorf("%w: ca.validity must have either 'years' or 'days' set in ca.yaml", domain.ErrValidation)
	}
	if cfg.CA.KeyAlgorithm == "" {
		return nil, fmt.Errorf("%w: ca.key_algorithm is required in ca.yaml", domain.ErrValidation)
	}

	return &cfg, nil
}

// LoadHosts loads the hosts configuration from hosts.yaml.
func (l *YAMLConfigLoader) LoadHosts() (*domain.HostsConfig, error) {
	path := filepath.Join(l.configPath, "hosts.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read hosts.yaml: %w", err)
	}

	var cfg domain.HostsConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse hosts.yaml: %w", err)
	}

	if reflect.ValueOf(cfg.Hosts).IsNil() {
		// This handles an empty or commented-out `hosts:` key.
		// We return an empty config instead of an error.
		return &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)}, nil
	}

	// Manual validation for each host
	for id, host := range cfg.Hosts {
		if host.Subject.CommonName == "" {
			return nil, fmt.Errorf("%w: hosts.%s.subject.common_name is required in hosts.yaml", domain.ErrValidation, id)
		}
		if host.Validity.Years == 0 && host.Validity.Days == 0 {
			return nil, fmt.Errorf("%w: hosts.%s.validity must have either 'years' or 'days' set in hosts.yaml", domain.ErrValidation, id)
		}
	}

	return &cfg, nil
}

=== internal/infra/crypto/service.go ===
package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/scrypt"
	"reactor.dev/reactor-ca/internal/domain"
)

// Service implements the domain.CryptoService interface.
type Service struct{}

// NewService creates a new crypto service.
func NewService() *Service {
	return &Service{}
}

// GeneratePrivateKey generates a new private key based on the specified algorithm.
func (s *Service) GeneratePrivateKey(algo domain.KeyAlgorithm) (crypto.Signer, error) {
	switch algo {
	case domain.RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case domain.RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case domain.RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case domain.ECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case domain.ECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case domain.ECP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case domain.ED25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// CreateRootCertificate creates a new self-signed CA certificate.
func (s *Service) CreateRootCertificate(cfg *domain.CAConfig, key crypto.Signer) (*x509.Certificate, error) {
	template, err := s.createBaseTemplate(&cfg.CA.Subject, cfg.CA.Validity)
	if err != nil {
		return nil, err
	}

	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.BasicConstraintsValid = true

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// CreateHostCertificate creates a new host certificate signed by the CA.
func (s *Service) CreateHostCertificate(hostCfg *domain.HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error) {
	template, err := s.createBaseTemplate(&hostCfg.Subject, hostCfg.Validity)
	if err != nil {
		return nil, err
	}

	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	template.DNSNames = append(template.DNSNames, hostCfg.AlternativeNames.DNS...)
	for _, ipStr := range hostCfg.AlternativeNames.IP {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	template.EmailAddresses = append(template.EmailAddresses, hostCfg.AlternativeNames.Email...)
	for _, uriStr := range hostCfg.AlternativeNames.URI {
		if uri, err := url.Parse(uriStr); err == nil {
			template.URIs = append(template.URIs, uri)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, hostPublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// SignCSR signs an external CSR with the CA key.
func (s *Service) SignCSR(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error) {
	serialNumber, err := s.newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(0, 0, validityDays).UTC(),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// EncryptPrivateKey encrypts a private key using PKCS#8 and AES-256-GCM with PBKDF2.
func (s *Service) EncryptPrivateKey(key crypto.Signer, password []byte) ([]byte, error) {
	// Using AES-256-GCM as it's a modern, authenticated encryption cipher.
	// Bumping KDF parameters for future-proofing.
	opts := pkcs8.Opts{
		Cipher: pkcs8.AES256GCM,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize: 16,
			// Increased iterations for better brute-force resistance.
			IterationCount: 600000,
			// Using SHA-512 for the KDF's HMAC.
			HMACHash: crypto.SHA512,
		},
	}

	encryptedDER, err := pkcs8.MarshalPrivateKey(key, password, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedDER,
	}), nil
}

// DecryptPrivateKey decrypts a PEM-encoded private key.
func (s *Service) DecryptPrivateKey(pemData, password []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
	if err != nil {
		// Check for specific error types to provide better UX.
		// The `youmark/pkcs8` library may not expose the exact error from x/crypto,
		// so we check for common error strings as a fallback.
		if errors.Is(err, pkcs8.ErrInvalidPassword) || errors.Is(err, scrypt.ErrUnsupportedParameter) || strings.Contains(strings.ToLower(err.Error()), "invalid password") {
			return nil, domain.ErrIncorrectPassword
		}
		return nil, fmt.Errorf("failed to parse/decrypt private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a crypto.Signer")
	}
	return signer, nil
}

// EncodeCertificateToPEM encodes a certificate to PEM format.
func (s *Service) EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// EncodeKeyToPEM encodes an unencrypted private key to PEM format.
func (s *Service) EncodeKeyToPEM(key crypto.Signer) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

// ParseCertificate parses a PEM-encoded certificate.
func (s *Service) ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKey parses an unencrypted PEM-encoded private key.
func (s *Service) ParsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback for older PKCS#1 RSA keys
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		// Fallback for older EC keys
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a crypto.Signer")
	}
	return signer, nil
}

// ParseCSR parses a PEM-encoded Certificate Signing Request.
func (s *Service) ParseCSR(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing CSR")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ValidateKeyPair checks if a private key and certificate belong together.
func (s *Service) ValidateKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return domain.ErrKeyCertMismatch
		}
	case *ecdsa.PublicKey:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return domain.ErrKeyCertMismatch
		}
	case ed25519.PublicKey:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return domain.ErrKeyCertMismatch
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
	return nil
}

// FormatCertificateInfo provides a human-readable summary of a certificate.
func (s *Service) FormatCertificateInfo(cert *x509.Certificate) string {
	var b strings.Builder
	b.WriteString("Certificate:\n")
	b.WriteString(fmt.Sprintf("    Version: %d\n", cert.Version))
	b.WriteString(fmt.Sprintf("    Serial Number: %s\n", cert.SerialNumber))
	b.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm))
	b.WriteString(fmt.Sprintf("    Issuer: %s\n", cert.Issuer.String()))
	b.WriteString("    Validity:\n")
	b.WriteString(fmt.Sprintf("        Not Before: %s\n", cert.NotBefore.Format(time.RFC1123)))
	b.WriteString(fmt.Sprintf("        Not After : %s\n", cert.NotAfter.Format(time.RFC1123)))
	b.WriteString(fmt.Sprintf("    Subject: %s\n", cert.Subject.String()))
	b.WriteString("    Subject Public Key Info:\n")
	b.WriteString(fmt.Sprintf("        Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm))
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		b.WriteString("    X509v3 Subject Alternative Name:\n")
		if len(cert.DNSNames) > 0 {
			b.WriteString(fmt.Sprintf("        DNS: %s\n", strings.Join(cert.DNSNames, ", ")))
		}
		if len(cert.IPAddresses) > 0 {
			var ips []string
			for _, ip := range cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			b.WriteString(fmt.Sprintf("        IP Address: %s\n", strings.Join(ips, ", ")))
		}
	}
	b.WriteString(fmt.Sprintf("    Is CA: %t\n", cert.IsCA))
	return b.String()
}

// createBaseTemplate creates a base certificate template.
func (s *Service) createBaseTemplate(subject *domain.SubjectConfig, validity domain.Validity) (*x509.Certificate, error) {
	serialNumber, err := s.newSerialNumber()
	if err != nil {
		return nil, err
	}

	pkixName := pkix.Name{
		CommonName:         subject.CommonName,
		Organization:       []string{subject.Organization},
		OrganizationalUnit: []string{subject.OrganizationUnit},
		Country:            []string{subject.Country},
		Province:           []string{subject.State},
		Locality:           []string{subject.Locality},
	}
	if subject.Email != "" {
		if _, err := mail.ParseAddress(subject.Email); err == nil {
			pkixName.ExtraNames = append(pkixName.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{1, 2, 840, 113549, 1, 9, 1}, // OID for email address
				Value: subject.Email,
			})
		}
	}

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkixName,
		NotBefore:             time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:              time.Now().Add(validity.ToDuration()).UTC(),
		BasicConstraintsValid: true,
	}, nil
}

// newSerialNumber generates a new, large, random serial number.
func (s *Service) newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

=== internal/app/application_test.go ===
package app_test

import (
	"context"
	"errors"
	"testing"

	"reactor.dev/reactor-ca/internal/app"
	"reactor.dev/reactor-ca/internal/domain"
)

// --- Mocks ---

type mockConfigLoader struct {
	ca    *domain.CAConfig
	hosts *domain.HostsConfig
	err   error
}

func (m *mockConfigLoader) LoadCA() (*domain.CAConfig, error) {
	return m.ca, m.err
}
func (m *mockCofigLoader) LoadHosts() (*domain.HostsConfig, error) {
	return m.hosts, m.err
}

type mockStore struct {
	hostIDs    []string
	deletedIDs []string
	err        error
}

func (m *mockStore) ListHostIDs() ([]string, error) {
	return m.hostIDs, m.err
}
func (m *mockStore) DeleteHost(hostID string) error {
	if m.err != nil {
		return m.err
	}
	m.deletedIDs = append(m.deletedIDs, hostID)
	return nil
}

// Add empty implementations for other Store methods to satisfy the interface
func (m *mockStore) CAExists() (bool, error)                            { return false, nil }
func (m *mockStore) SaveCA(cert, encryptedKey []byte) error              { return nil }
func (m *mockStore) LoadCACert() (*x509.Certificate, error)              { return nil, nil }
func (m *mockStore) LoadCAKey() ([]byte, error)                          { return nil, nil }
func (m *mockStore) HostExists(hostID string) (bool, error)              { return false, nil }
func (m *mockStore) HostKeyExists(hostID string) (bool, error)           { return false, nil }
func (m *mockStore) SaveHostCert(hostID string, cert []byte) error       { return nil }
func (m *mockStore) SaveHostKey(hostID string, encryptedKey []byte) error { return nil }
func (m *mockStore) LoadHostCert(hostID string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockStore) LoadHostKey(hostID string) ([]byte, error) { return nil, nil }
func (m *mockStore) GetAllEncryptedKeyPaths() ([]string, error)  { return nil, nil }
func (m *mockStore) UpdateEncryptedKey(path string, data []byte) error {
	return nil
}
func (m *mockStore) GetHostCertPath(hostID string) string { return "" }
func (m *mockStore) GetHostKeyPath(hostID string) string  { return "" }
func (m *mockStore) GetCACertPath() string                { return "" }

type mockPasswordProvider struct {
	confirmResponse bool
	confirmErr      error
}

func (m *mockPasswordProvider) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, m.confirmErr
}

// Add empty implementations for other PasswordProvider methods
func (m *mockPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}

// --- Tests ---

func TestCleanHosts(t *testing.T) {
	testCases := []struct {
		name              string
		storeIDs          []string
		configIDs         []string
		force             bool
		confirmResponse   bool
		confirmError      error
		expectedPruned    []string
		expectedErr       error
		expectStoreDelete bool
	}{
		{
			name:           "No hosts to prune",
			storeIDs:       []string{"host1", "host2"},
			configIDs:      []string{"host1", "host2"},
			force:          true,
			expectedPruned: nil,
			expectedErr:    nil,
		},
		{
			name:              "Prune one host with force",
			storeIDs:          []string{"host1", "host2-to-prune"},
			configIDs:         []string{"host1"},
			force:             true,
			expectedPruned:    []string{"host2-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:              "Prune multiple hosts with confirmation",
			storeIDs:          []string{"host1", "host2-to-prune", "host3-to-prune"},
			configIDs:         []string{"host1"},
			force:             false,
			confirmResponse:   true,
			expectedPruned:    []string{"host2-to-prune", "host3-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:            "Prune aborted by user",
			storeIDs:        []string{"host1", "host2-to-prune"},
			configIDs:       []string{"host1"},
			force:           false,
			confirmResponse: false,
			expectedPruned:  nil,
			expectedErr:     domain.ErrActionAborted,
		},
		{
			name:            "Confirmation fails",
			storeIDs:        []string{"host1", "host2-to-prune"},
			configIDs:       []string{"host1"},
			force:           false,
			confirmError:    errors.New("input error"),
			expectedPruned:  nil,
			expectedErr:     errors.New("input error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Mocks
			mockCfgLoader := &mockConfigLoader{
				hosts: &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)},
			}
			for _, id := range tc.configIDs {
				mockCfgLoader.hosts.Hosts[id] = domain.HostConfig{}
			}

			mockStore := &mockStore{
				hostIDs: tc.storeIDs,
			}

			mockPwProvider := &mockPasswordProvider{
				confirmResponse: tc.confirmResponse,
				confirmErr:      tc.confirmError,
			}

			// Create Application instance
			application := app.NewApplication("", nil, mockCfgLoader, mockStore, nil, mockPwProvider, nil)

			// Run the method
			pruned, err := application.CleanHosts(context.Background(), tc.force)

			// Assertions
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
			}

			if len(pruned) != len(tc.expectedPruned) {
				t.Fatalf("expected %d pruned hosts, got %d", len(tc.expectedPruned), len(pruned))
			}

			if tc.expectStoreDelete {
				if len(mockStore.deletedIDs) != len(tc.expectedPruned) {
					t.Errorf("expected %d calls to store.DeleteHost, got %d", len(tc.expectedPruned), len(mockStore.deletedIDs))
				}
			} else {
				if len(mockStore.deletedIDs) > 0 {
					t.Errorf("expected no calls to store.DeleteHost, but got %d", len(mockStore.deletedIDs))
				}
			}
		})
	}
}
```

---
Tokens: 34002 input, 23250 output, 60826 total
Cost: $0.042502 input + $0.232500 output = $0.275002 total
