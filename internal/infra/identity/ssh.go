package identity

import (
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/pathutil"
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
	identityPath := pathutil.ExpandHomePath(s.config.IdentityFile)

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
	identityPath := pathutil.ExpandHomePath(s.config.IdentityFile)
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
