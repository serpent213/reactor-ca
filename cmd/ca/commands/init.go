package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/serpent213/reactor-ca/internal/ui"
	"github.com/spf13/cobra"
)

var forceInit bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize config and store directories",
	Long:  `Creates the necessary directory structure (config/, store/) and populates it with default configuration files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootPath, err := getRootPath(cmd)
		if err != nil {
			return err
		}

		ui.Action("Initializing Reactor CA in %s...", rootPath)

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
			ui.Success("Created directory: %s", dir)
		}

		files := map[string]string{
			filepath.Join(rootPath, "config", "ca.yaml"):    defaultCaYAML,
			filepath.Join(rootPath, "config", "hosts.yaml"): defaultHostsYAML,
		}

		for path, content := range files {
			if _, err := os.Stat(path); err == nil && !forceInit {
				ui.Warning("Skipping existing file: %s (use --force to overwrite)", path)
				continue
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write file %s: %w", path, err)
			}
			ui.Success("Created config file: %s", path)
		}

		ui.Success("Initialization complete. Review the files in config/ and then run 'reactor-ca ca create'.")
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
