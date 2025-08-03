package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"reactor.de/reactor-ca/internal/domain"
)

// YAMLConfigUpdater implements the domain.ConfigWriter interface for YAML files.
type YAMLConfigUpdater struct {
	configPath string
	loader     domain.ConfigLoader
}

// NewYAMLConfigUpdater creates a new config updater.
func NewYAMLConfigUpdater(configPath string, loader domain.ConfigLoader) *YAMLConfigUpdater {
	return &YAMLConfigUpdater{
		configPath: configPath,
		loader:     loader,
	}
}

// RenameHost renames a host entry in hosts.yaml using regex replacement to preserve comments and formatting.
func (u *YAMLConfigUpdater) RenameHost(oldHostID, newHostID string) error {
	// Validate inputs
	if oldHostID == "" || newHostID == "" {
		return fmt.Errorf("%w: host IDs cannot be empty", domain.ErrValidation)
	}
	if oldHostID == newHostID {
		return fmt.Errorf("%w: old and new host IDs must be different", domain.ErrValidation)
	}

	// Validate that old host exists in config and new host doesn't
	hostsConfig, err := u.loader.LoadHosts()
	if err != nil {
		return fmt.Errorf("failed to load hosts config: %w", err)
	}

	if _, exists := hostsConfig.Hosts[oldHostID]; !exists {
		return fmt.Errorf("%w: host '%s' not found in configuration", domain.ErrHostNotFoundInConfig, oldHostID)
	}

	if _, exists := hostsConfig.Hosts[newHostID]; exists {
		return fmt.Errorf("%w: host '%s' already exists in configuration", domain.ErrValidation, newHostID)
	}

	// Read the hosts.yaml file
	hostsPath := filepath.Join(u.configPath, "hosts.yaml")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts.yaml: %w", err)
	}

	// Create regex pattern to match the host entry line
	// Pattern: ^(\s+)oldHostID:
	// This captures the leading whitespace and matches the host ID followed by a colon
	pattern := fmt.Sprintf(`^(\s+)%s:`, regexp.QuoteMeta(oldHostID))
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	// Replace the first match only
	content := string(data)
	lines := strings.Split(content, "\n")
	replaced := false

	for i, line := range lines {
		if re.MatchString(line) {
			// Replace with preserved indentation
			lines[i] = re.ReplaceAllString(line, fmt.Sprintf("${1}%s:", newHostID))
			replaced = true
			break // Stop after first match as requested
		}
	}

	if !replaced {
		return fmt.Errorf("%w: host entry '%s' not found in hosts.yaml file structure", domain.ErrHostNotFoundInConfig, oldHostID)
	}

	// Join lines back together
	newContent := strings.Join(lines, "\n")

	// Create backup file
	backupPath := hostsPath + ".bak"
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}

	// Write the updated content atomically
	tempPath := hostsPath + ".tmp"
	if err := os.WriteFile(tempPath, []byte(newContent), 0600); err != nil {
		os.Remove(backupPath) // Clean up backup on failure
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Validate the updated configuration
	if err := u.loader.ValidateHostsConfig([]byte(newContent)); err != nil {
		os.Remove(tempPath)   // Clean up temp file
		os.Remove(backupPath) // Clean up backup
		return fmt.Errorf("validation failed after rename: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, hostsPath); err != nil {
		os.Remove(tempPath)   // Clean up temp file
		os.Remove(backupPath) // Clean up backup
		return fmt.Errorf("failed to update hosts.yaml: %w", err)
	}

	// Clean up backup file on success
	os.Remove(backupPath)

	return nil
}
