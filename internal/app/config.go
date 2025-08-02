package app

import (
	"context"
	"fmt"

	"reactor.de/reactor-ca/internal/domain"
)

// ValidateConfig checks if the configuration files are valid.
func (a *Application) ValidateConfig(ctx context.Context) error {
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}

	// Validate each host configuration, including additional recipients
	for hostID, hostCfg := range hostsCfg.Hosts {
		if err := a.validateHostConfig(caCfg, &hostCfg, hostID); err != nil {
			return fmt.Errorf("validation failed for host '%s': %w", hostID, err)
		}
	}

	return nil
}

// validateHostConfig validates a single host configuration.
func (a *Application) validateHostConfig(caCfg *domain.CAConfig, hostCfg *domain.HostConfig, hostID string) error {
	// If no host-specific encryption, nothing to validate
	if hostCfg.Encryption == nil || len(hostCfg.Encryption.AdditionalRecipients) == 0 {
		return nil
	}

	// Check that CA provider supports additional recipients
	if caCfg.Encryption.Provider != "ssh" && caCfg.Encryption.Provider != "plugin" {
		return fmt.Errorf("additional_recipients require CA encryption provider to be 'ssh' or 'plugin', got '%s'", caCfg.Encryption.Provider)
	}

	return nil
}
