package identity

import (
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/ui"
)

// MergedProvider combines a base identity provider with additional recipients.
// It can decrypt using the base provider's identity but encrypts for both
// base and additional recipients.
type MergedProvider struct {
	baseProvider         domain.IdentityProvider
	additionalRecipients []string
	providerType         string
	ui                   *plugin.ClientUI
}

// NewMergedProvider creates a new merged identity provider.
func NewMergedProvider(baseProvider domain.IdentityProvider, additionalRecipients []string, providerType string) *MergedProvider {
	return &MergedProvider{
		baseProvider:         baseProvider,
		additionalRecipients: additionalRecipients,
		providerType:         providerType,
		ui:                   ui.NewAgePluginUI(),
	}
}

// GetIdentity returns the base provider's identity for decryption.
// Only the base provider can decrypt - additional recipients are encryption-only.
func (m *MergedProvider) GetIdentity() (age.Identity, error) {
	return m.baseProvider.GetIdentity()
}

// GetRecipients returns combined recipients from base provider and additional recipients.
func (m *MergedProvider) GetRecipients() ([]age.Recipient, error) {
	// Get base recipients
	baseRecipients, err := m.baseProvider.GetRecipients()
	if err != nil {
		return nil, fmt.Errorf("failed to get base recipients: %w", err)
	}

	// Parse additional recipients based on provider type
	additionalRecipients, err := m.parseAdditionalRecipients()
	if err != nil {
		return nil, fmt.Errorf("failed to parse additional recipients: %w", err)
	}

	// Merge and return
	return append(baseRecipients, additionalRecipients...), nil
}

// parseAdditionalRecipients parses additional recipients based on the provider type.
func (m *MergedProvider) parseAdditionalRecipients() ([]age.Recipient, error) {
	if len(m.additionalRecipients) == 0 {
		return nil, nil
	}

	var recipients []age.Recipient
	for i, recipientStr := range m.additionalRecipients {
		recipientStr = strings.TrimSpace(recipientStr)
		if recipientStr == "" {
			continue
		}

		recipient, err := m.parseRecipient(recipientStr, i)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}

// parseRecipient parses a single recipient string into an age.Recipient.
func (m *MergedProvider) parseRecipient(recipientStr string, index int) (age.Recipient, error) {
	// SSH public key format
	if strings.HasPrefix(recipientStr, "ssh-") {
		recipient, err := agessh.ParseRecipient(recipientStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH recipient at index %d (%q): %w", index, recipientStr, err)
		}
		return recipient, nil
	}

	// Age plugin recipient format
	if strings.HasPrefix(recipientStr, "age1") {
		// Try standard age recipient first
		if recipient, err := age.ParseX25519Recipient(recipientStr); err == nil {
			return recipient, nil
		}

		// Try plugin recipient
		recipient, err := plugin.NewRecipient(recipientStr, m.ui)
		if err != nil {
			return nil, fmt.Errorf("invalid age recipient at index %d (%q): %w", index, recipientStr, err)
		}
		return recipient, nil
	}

	return nil, fmt.Errorf("unsupported recipient format at index %d (%q): must be SSH public key (ssh-*) or age recipient (age1*)", index, recipientStr)
}

// Validate checks the merged provider configuration.
func (m *MergedProvider) Validate() error {
	// Validate base provider
	if err := m.baseProvider.Validate(); err != nil {
		return fmt.Errorf("base provider validation failed: %w", err)
	}

	// Validate additional recipients
	if len(m.additionalRecipients) == 0 {
		return nil // No additional recipients is valid
	}

	for i, recipientStr := range m.additionalRecipients {
		recipientStr = strings.TrimSpace(recipientStr)
		if recipientStr == "" {
			continue
		}

		if _, err := m.parseRecipient(recipientStr, i); err != nil {
			return err
		}
	}

	return nil
}
