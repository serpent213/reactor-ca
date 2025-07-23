package identity

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/serpent213/reactor-ca/internal/domain"
	"github.com/serpent213/reactor-ca/internal/ui"
)

// PluginProvider implements domain.IdentityProvider using age plugins.
// It works with any age-plugin-* binary (secure-enclave, yubikey, tpm, etc.)
type PluginProvider struct {
	config domain.PluginConfig
	ui     *plugin.ClientUI
}

// NewPluginProvider creates a new age plugin-based identity provider.
func NewPluginProvider(config domain.PluginConfig) *PluginProvider {
	return &PluginProvider{
		config: config,
		ui:     ui.NewAgePluginUI(),
	}
}

// GetIdentity returns the plugin-based age identity for decryption.
func (p *PluginProvider) GetIdentity() (age.Identity, error) {
	identityPath := p.expandPath(p.config.IdentityFile)

	identityData, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin identity file %q: %w", identityPath, err)
	}

	// Parse the identity file to get the plugin identity string
	identityStr := strings.TrimSpace(string(identityData))
	if identityStr == "" {
		return nil, fmt.Errorf("plugin identity file %q is empty", identityPath)
	}

	// Extract first line if multiline (age identity files can have comments)
	lines := strings.Split(identityStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			identityStr = line
			break
		}
	}

	if !strings.HasPrefix(identityStr, "AGE-PLUGIN-") {
		return nil, fmt.Errorf("invalid plugin identity format in %q: must start with AGE-PLUGIN-", identityPath)
	}

	identity, err := plugin.NewIdentity(identityStr, p.ui)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin identity from %q: %w", identityPath, err)
	}

	return identity, nil
}

// GetRecipients returns the plugin-based age recipients for encryption.
func (p *PluginProvider) GetRecipients() ([]age.Recipient, error) {
	if len(p.config.Recipients) == 0 {
		return nil, fmt.Errorf("no plugin recipients configured")
	}

	var recipients []age.Recipient
	for i, recipientStr := range p.config.Recipients {
		recipientStr = strings.TrimSpace(recipientStr)
		if !strings.HasPrefix(recipientStr, "age1") {
			return nil, fmt.Errorf("invalid plugin recipient at index %d (%q): must start with age1", i, recipientStr)
		}

		recipient, err := plugin.NewRecipient(recipientStr, p.ui)
		if err != nil {
			return nil, fmt.Errorf("invalid plugin recipient at index %d (%q): %w", i, recipientStr, err)
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}

// Validate checks the plugin provider configuration.
func (p *PluginProvider) Validate() error {
	// Check identity file exists and is readable
	identityPath := p.expandPath(p.config.IdentityFile)
	if _, err := os.Stat(identityPath); err != nil {
		return fmt.Errorf("plugin identity file not accessible: %w", err)
	}

	// Check if we can parse the identity file
	identityData, err := os.ReadFile(identityPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin identity file: %w", err)
	}

	identityStr := strings.TrimSpace(string(identityData))
	if identityStr == "" {
		return fmt.Errorf("plugin identity file is empty")
	}

	// Extract first non-comment line
	lines := strings.Split(identityStr, "\n")
	var validIdentity string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			validIdentity = line
			break
		}
	}

	if !strings.HasPrefix(validIdentity, "AGE-PLUGIN-") {
		return fmt.Errorf("plugin identity file contains invalid identity format: must start with AGE-PLUGIN-")
	}

	// Try to create identity to validate format
	if _, err := plugin.NewIdentity(validIdentity, p.ui); err != nil {
		return fmt.Errorf("plugin identity file contains invalid identity: %w", err)
	}

	// Validate recipients
	if len(p.config.Recipients) == 0 {
		return fmt.Errorf("no plugin recipients configured")
	}

	for i, recipientStr := range p.config.Recipients {
		recipientStr = strings.TrimSpace(recipientStr)
		if !strings.HasPrefix(recipientStr, "age1") {
			return fmt.Errorf("invalid plugin recipient at index %d: must start with age1", i)
		}

		if _, err := plugin.NewRecipient(recipientStr, p.ui); err != nil {
			return fmt.Errorf("invalid plugin recipient at index %d: %w", i, err)
		}
	}

	return nil
}

// expandPath expands ~ to the user's home directory.
func (p *PluginProvider) expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to original path if we can't get home directory
		return path
	}

	return homeDir + path[1:] // Remove ~ and keep the /
}
