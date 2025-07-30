package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/ui"
)

var forceInit bool

// SSHKeyInfo holds information about a detected SSH key
type SSHKeyInfo struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKeyData  string
	KeyType        string
}

// detectSSHKeys finds available SSH keys, preferring ed25519 over rsa
func detectSSHKeys() (*SSHKeyInfo, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("unable to determine home directory: %w", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	// Preferred key types in order (ed25519, then rsa)
	keyTypes := []string{"id_ed25519", "id_rsa"}

	for _, keyType := range keyTypes {
		privateKeyPath := filepath.Join(sshDir, keyType)
		publicKeyPath := privateKeyPath + ".pub"

		// Check if both private and public key exist
		if _, err := os.Stat(privateKeyPath); err != nil {
			continue
		}
		if _, err := os.Stat(publicKeyPath); err != nil {
			continue
		}

		// Read public key data
		pubKeyBytes, err := os.ReadFile(publicKeyPath)
		if err != nil {
			continue
		}

		pubKeyData := strings.TrimSpace(string(pubKeyBytes))
		if pubKeyData == "" {
			continue
		}

		// Determine actual key type from public key content
		actualKeyType := "unknown"
		if strings.Contains(pubKeyData, "ssh-ed25519") {
			actualKeyType = "ed25519"
		} else if strings.Contains(pubKeyData, "ssh-rsa") {
			actualKeyType = "rsa"
		}

		return &SSHKeyInfo{
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
			PublicKeyData:  pubKeyData,
			KeyType:        actualKeyType,
		}, nil
	}

	return nil, fmt.Errorf("no usable SSH keys found (looked for id_ed25519, id_rsa)")
}

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

		// Detect SSH keys for smart configuration
		sshKey, sshErr := detectSSHKeys()
		var caConfig string

		if sshErr == nil {
			// SSH key found - use SSH-based encryption
			ui.Info("Detected %s SSH key: %s", sshKey.KeyType, sshKey.PrivateKeyPath)
			caConfig = generateCaConfig(sshKey)
		} else {
			// No SSH key - fall back to password-based encryption
			ui.Warning("No SSH keys detected, using password-based encryption")
			ui.Info("(Looked for ~/.ssh/id_ed25519 and ~/.ssh/id_rsa)")
			caConfig = generateCaConfig(nil)
		}

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
			filepath.Join(rootPath, "config", "ca.yaml"):    caConfig,
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

		if sshErr == nil {
			ui.Success("Configured SSH-based encryption using your %s public key", sshKey.KeyType)
		} else {
			ui.Success("Configured password-based encryption (set REACTOR_CA_PASSWORD or use interactive prompt)")
		}

		ui.Success("Initialization complete. Review the files in config/ and then run “ca ca create”.")
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Overwrite existing configuration files")
}

// generateCaConfig creates a ca.yaml configuration based on detected SSH key or password fallback
func generateCaConfig(sshKey *SSHKeyInfo) string {
	if sshKey == nil {
		return fmt.Sprintf(baseCaTemplate, passwordEncryptionSection)
	}

	// Convert absolute path to relative path with ~ if it's in home directory
	identityPath := sshKey.PrivateKeyPath
	if homeDir, err := os.UserHomeDir(); err == nil {
		if strings.HasPrefix(identityPath, homeDir) {
			identityPath = "~" + identityPath[len(homeDir):]
		}
	}

	encryptionSection := fmt.Sprintf(sshEncryptionSection, sshKey.KeyType, identityPath, sshKey.PublicKeyData)
	return fmt.Sprintf(baseCaTemplate, encryptionSection)
}

const baseCaTemplate = `# ReactorCA: Certificate Authority Configuration
# This file defines the properties of your root Certificate Authority.
# yaml-language-server: $schema=https://serpent213.github.io/reactor-ca/schemas/v1/ca.schema.json

ca:
  # These values are used to build the distinguished name (DN) of the CA certificate.
  subject:
    common_name: Reactor Homelab CA
    organization: Reactor Industries
    organization_unit: EDV
    country: DE                 # 2-letter country code
    state: Niedersachsen        # State or province
    locality: Springfeld        # City or locality
    email: "admin@example.dev"  # Administrative contact

  # How long the CA certificate will be valid for.
  # Specify any combination of 'years', 'months' and 'days'.
  validity:
    years: 10
    # days: 3650

  # The algorithm used for the CA's private key.
  # Supported: RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519
  key_algorithm: ECP384
  # The hash algorithm used for the certificate signature.
  # Supported: SHA256, SHA384, SHA512
  hash_algorithm: SHA384

%s`

const sshEncryptionSection = `# Defines how private keys are encrypted on disk using age.
encryption:
  # Provider: password | ssh | plugin
  provider: ssh

  # SSH key-based encryption settings (using age-ssh)
  # Auto-detected %s SSH key
  ssh:
    identity_file: "%s"
    recipients:
      - "%s"
`

const passwordEncryptionSection = `# Defines how private keys are encrypted on disk using age.
encryption:
  # Provider: password | ssh | plugin
  provider: password

  # Password-based encryption settings (using age scrypt)
  # Set REACTOR_CA_PASSWORD environment variable or use interactive prompt
  password:
    min_length: 12

  # SSH key-based encryption settings (using age-ssh)
  # ssh:
  #   identity_file: "~/.ssh/id_ed25519"
  #   recipients:
  #     - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmlSRRC4SIrIvVCIvH+H9GvhDxGbus907IJByMtgJIm user@host"
`

const defaultHostsYAML = `# ReactorCA: Host Certificate Configuration
# This file defines the certificates you want to issue for your hosts/services.
# yaml-language-server: $schema=https://serpent213.github.io/reactor-ca/schemas/v1/hosts.schema.json

hosts:
  # This is a unique ID for the certificate, used in CLI commands (e.g., 'ca host issue web-server').
  web-server-example:
    # Subject is optional and will inherit from ca.yaml if not specified (except for 'common_name').
    # subject:
    #   common_name: web.reactor.local
    #   organization_unit: "Web Services"

    # The names (SANs) the certificate should be valid for. Make sure they match!
    alternative_names:
      dns:
        - web.reactor.local
        - grafana.reactor.local
      ip:
        - 192.168.1.100
        - 10.10.0.1

    # How long the host certificate will be valid for.
    validity:
      years: 1
      # days: 365

    # Algorithm for this specific host's key. Defaults to CA's key_algorithm if unset.
    # Supported: RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519
    key_algorithm: RSA2048
    # Signing hash for this specific certificate. Defaults to CA's hash_algorithm if unset.
    # Supported: SHA256, SHA384, SHA512
    hash_algorithm: SHA256

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
      command: |
        # scp ${chain} ${cert} user@host:/etc/ssl/certs/
        # ssh user@host -- 'systemctl reload nginx'
        echo 'Deployment for web-server-example would run now.'
        echo 'Cert Path: ${cert}'
        echo 'Key Path: ${private_key}'
`
