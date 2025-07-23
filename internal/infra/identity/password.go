package identity

import (
	"context"
	"fmt"

	"filippo.io/age"

	"github.com/serpent213/reactor-ca/internal/domain"
)

// PasswordProvider implements IdentityProvider using scrypt-based age encryption.
type PasswordProvider struct {
	config         domain.PasswordConfig
	passwordGetter domain.PasswordProvider
}

// NewPasswordProvider creates a new password-based identity provider.
func NewPasswordProvider(config domain.PasswordConfig, passwordGetter domain.PasswordProvider) *PasswordProvider {
	return &PasswordProvider{
		config:         config,
		passwordGetter: passwordGetter,
	}
}

// GetIdentity returns an age.Identity for decryption.
func (p *PasswordProvider) GetIdentity() (age.Identity, error) {
	password, err := p.getMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	identity, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to create scrypt identity: %w", err)
	}

	return identity, nil
}

// GetRecipients returns age.Recipients for encryption.
func (p *PasswordProvider) GetRecipients() ([]age.Recipient, error) {
	password, err := p.getMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	recipient, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to create scrypt recipient: %w", err)
	}

	return []age.Recipient{recipient}, nil
}

// Validate checks if the provider configuration is valid.
func (p *PasswordProvider) Validate() error {
	if p.config.MinLength <= 0 {
		return fmt.Errorf("password min_length must be positive")
	}

	// Try to get password to validate configuration
	_, err := p.getMasterPassword()
	if err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	return nil
}

// getMasterPassword retrieves the master password using the configured method.
func (p *PasswordProvider) getMasterPassword() ([]byte, error) {
	ctx := context.Background()
	return p.passwordGetter.GetMasterPassword(ctx, p.config)
}
