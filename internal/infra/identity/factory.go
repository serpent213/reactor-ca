package identity

import (
	"fmt"

	"reactor.de/reactor-ca/internal/domain"
)

// Factory implements domain.IdentityProviderFactory.
type Factory struct{}

// NewFactory creates a new identity provider factory.
func NewFactory() *Factory {
	return &Factory{}
}

// CreateIdentityProvider creates an identity provider based on configuration.
func (f *Factory) CreateIdentityProvider(cfg *domain.CAConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	switch cfg.Encryption.Provider {
	case "", "password":
		return NewPasswordProvider(cfg.Encryption.Password, passwordProvider), nil
	case "ssh":
		provider := NewSSHProvider(cfg.Encryption.SSH)
		if err := provider.Validate(); err != nil {
			return nil, fmt.Errorf("SSH provider validation failed: %w", err)
		}
		return provider, nil
	case "plugin":
		provider := NewPluginProvider(cfg.Encryption.Plugin)
		if err := provider.Validate(); err != nil {
			return nil, fmt.Errorf("plugin provider validation failed: %w", err)
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported encryption provider: %s", cfg.Encryption.Provider)
	}
}

// CreateHostIdentityProvider creates an identity provider for a specific host,
// potentially merging additional recipients with the base CA provider.
func (f *Factory) CreateHostIdentityProvider(cfg *domain.CAConfig, hostConfig *domain.HostConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	// Create base provider
	baseProvider, err := f.CreateIdentityProvider(cfg, passwordProvider)
	if err != nil {
		return nil, err
	}

	// If no host-specific encryption config, use base provider
	if hostConfig.Encryption == nil || len(hostConfig.Encryption.AdditionalRecipients) == 0 {
		return baseProvider, nil
	}

	// Create merged provider with additional recipients
	mergedProvider := NewMergedProvider(baseProvider, hostConfig.Encryption.AdditionalRecipients, cfg.Encryption.Provider)
	if err := mergedProvider.Validate(); err != nil {
		return nil, fmt.Errorf("merged provider validation failed: %w", err)
	}

	return mergedProvider, nil
}
