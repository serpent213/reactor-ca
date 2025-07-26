package identity

import (
	"context"
	"fmt"

	"filippo.io/age"

	"reactor.de/reactor-ca/internal/domain"
)

// PasswordProvider implements IdentityProvider using scrypt-based age encryption.
type PasswordProvider struct {
	config         domain.PasswordConfig
	passwordGetter domain.PasswordProvider

	// Cache password for session to avoid repeated prompts
	cachedPassword   []byte
	cachedIdentity   age.Identity
	cachedRecipients []age.Recipient
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
	// Return cached identity if available
	if p.cachedIdentity != nil {
		return p.cachedIdentity, nil
	}

	password, err := p.getMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	identity, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to create scrypt identity: %w", err)
	}

	// Cache the identity for session reuse
	p.cachedIdentity = identity
	return identity, nil
}

// GetRecipients returns age.Recipients for encryption.
func (p *PasswordProvider) GetRecipients() ([]age.Recipient, error) {
	// Return cached recipients if available
	if p.cachedRecipients != nil {
		return p.cachedRecipients, nil
	}

	password, err := p.getMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	recipient, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to create scrypt recipient: %w", err)
	}

	// Cache the recipients for session reuse
	p.cachedRecipients = []age.Recipient{recipient}
	return p.cachedRecipients, nil
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
	// Return cached password if available
	if p.cachedPassword != nil {
		return p.cachedPassword, nil
	}

	ctx := context.Background()
	password, err := p.passwordGetter.GetMasterPassword(ctx, p.config)
	if err != nil {
		return nil, err
	}

	// Cache the password for session reuse
	p.cachedPassword = password
	return password, nil
}
