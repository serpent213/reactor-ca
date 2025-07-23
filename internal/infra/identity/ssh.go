package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"reactor.de/reactor-ca/internal/domain"
)

// SSHProvider implements domain.IdentityProvider using SSH keys for age encryption.
type SSHProvider struct {
	config domain.SSHConfig
}

// NewSSHProvider creates a new SSH-based identity provider.
func NewSSHProvider(config domain.SSHConfig) *SSHProvider {
	return &SSHProvider{
		config: config,
	}
}

// GetIdentity returns the SSH-based age identity for decryption.
func (s *SSHProvider) GetIdentity() (age.Identity, error) {
	identityPath := s.expandPath(s.config.IdentityFile)

	keyBytes, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH identity file %q: %w", identityPath, err)
	}

	identity, err := agessh.ParseIdentity(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH identity from %q: %w", identityPath, err)
	}

	return identity, nil
}

// GetRecipients returns the SSH-based age recipients for encryption.
func (s *SSHProvider) GetRecipients() ([]age.Recipient, error) {
	if len(s.config.Recipients) == 0 {
		return nil, fmt.Errorf("no SSH recipients configured")
	}

	var recipients []age.Recipient
	for i, pubKey := range s.config.Recipients {
		recipient, err := agessh.ParseRecipient(pubKey)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH recipient at index %d (%q): %w", i, pubKey, err)
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}

// Validate checks the SSH provider configuration.
func (s *SSHProvider) Validate() error {
	// Check identity file exists and is readable
	identityPath := s.expandPath(s.config.IdentityFile)
	if _, err := os.Stat(identityPath); err != nil {
		return fmt.Errorf("SSH identity file not accessible: %w", err)
	}

	// Check if we can parse the identity file
	keyBytes, err := os.ReadFile(identityPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH identity file: %w", err)
	}

	if _, err := agessh.ParseIdentity(keyBytes); err != nil {
		return fmt.Errorf("SSH identity file is not a valid SSH private key: %w", err)
	}

	// Validate recipients
	if len(s.config.Recipients) == 0 {
		return fmt.Errorf("no SSH recipients configured")
	}

	for i, pubKey := range s.config.Recipients {
		if _, err := agessh.ParseRecipient(pubKey); err != nil {
			return fmt.Errorf("invalid SSH recipient at index %d: %w", i, err)
		}
	}

	return nil
}

// ClearIdentityCache is a no-op for SSH provider as it doesn't cache identities.
func (s *SSHProvider) ClearIdentityCache() {
	// No-op: SSH provider creates fresh identities on each call
}

// expandPath expands ~ to the user's home directory.
func (s *SSHProvider) expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to original path if we can't get home directory
		return path
	}

	return filepath.Join(homeDir, path[2:])
}
