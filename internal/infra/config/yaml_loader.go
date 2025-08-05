package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/crypto/extensions"
)

// YAMLConfigLoader implements the domain.ConfigLoader interface for YAML files.
type YAMLConfigLoader struct {
	configPath       string
	extensionFactory domain.ExtensionFactory
}

// NewYAMLConfigLoader creates a new config loader.
func NewYAMLConfigLoader(configPath string) *YAMLConfigLoader {
	return &YAMLConfigLoader{
		configPath:       configPath,
		extensionFactory: extensions.NewRegistry(),
	}
}

// LoadCA loads the CA configuration from ca.yaml.
func (l *YAMLConfigLoader) LoadCA() (*domain.CAConfig, error) {
	path := filepath.Join(l.configPath, "ca.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ca.yaml: %w", err)
	}

	// Validate against JSON schema first
	if err := l.ValidateCAConfig(data); err != nil {
		return nil, fmt.Errorf("validation error: ca.yaml: %w", err)
	}

	var cfg domain.CAConfig
	// Use a decoder to get strict unmarshalling
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse ca.yaml: %w", err)
	}

	// Manual validation
	// Note: CommonName is optional following CA best practices (RFC 9525)
	if cfg.CA.Validity.Years == 0 && cfg.CA.Validity.Months == 0 && cfg.CA.Validity.Days == 0 {
		return nil, fmt.Errorf("%w: ca.validity must have either 'years', 'months', or 'days' set in ca.yaml", domain.ErrValidation)
	}
	if cfg.CA.KeyAlgorithm == "" {
		return nil, fmt.Errorf("%w: ca.key_algorithm is required in ca.yaml", domain.ErrValidation)
	}
	if cfg.CA.HashAlgorithm == "" {
		return nil, fmt.Errorf("%w: ca.hash_algorithm is required in ca.yaml", domain.ErrValidation)
	}

	// Validate extensions configuration
	if err := l.validateExtensions(cfg.CA.Extensions, "ca.extensions"); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadHosts loads the hosts configuration from hosts.yaml.
func (l *YAMLConfigLoader) LoadHosts() (*domain.HostsConfig, error) {
	path := filepath.Join(l.configPath, "hosts.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read hosts.yaml: %w", err)
	}

	// Validate against JSON schema first
	if err := l.ValidateHostsConfig(data); err != nil {
		return nil, fmt.Errorf("validation error: hosts.yaml: %w", err)
	}

	var cfg domain.HostsConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse hosts.yaml: %w", err)
	}

	if reflect.ValueOf(cfg.Hosts).IsNil() {
		// This handles an empty or commented-out `hosts:` key.
		// We return an empty config instead of an error.
		return &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)}, nil
	}

	// Manual validation for each host
	for id, host := range cfg.Hosts {
		// CommonName is optional following CA best practices (RFC 9525)
		// If CN is specified, it must be present in SAN DNS names for browser compatibility
		if host.Subject.CommonName != "" {
			cnInSAN := false
			for _, dnsName := range host.AlternativeNames.DNS {
				if dnsName == host.Subject.CommonName {
					cnInSAN = true
					break
				}
			}
			if !cnInSAN {
				return nil, fmt.Errorf("%w: hosts.%s.subject.common_name '%s' must be included in alternative_names.dns for modern browser compatibility", domain.ErrValidation, id, host.Subject.CommonName)
			}
		}

		if host.Validity.Years == 0 && host.Validity.Months == 0 && host.Validity.Days == 0 {
			return nil, fmt.Errorf("%w: hosts.%s.validity must have either 'years', 'months', or 'days' set in hosts.yaml", domain.ErrValidation, id)
		}

		// Validate extensions configuration for this host
		if err := l.validateExtensions(host.Extensions, fmt.Sprintf("hosts.%s.extensions", id)); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// validateExtensions validates the extensions configuration
func (l *YAMLConfigLoader) validateExtensions(extensions domain.ExtensionsConfig, configPath string) error {
	if len(extensions) == 0 {
		return nil // No extensions to validate
	}

	for name, rawConfig := range extensions {
		// Check if it's a known extension
		if l.extensionFactory.IsRegistered(name) {
			// Try to parse the known extension to validate its configuration
			ext := l.extensionFactory.CreateExtension(name)
			if err := ext.ParseFromYAML(rawConfig.Critical, rawConfig.Fields); err != nil {
				return fmt.Errorf("%w: %s.%s: %v", domain.ErrValidation, configPath, name, err)
			}
		} else {
			// For unknown extensions, validate that they have required fields
			if err := l.validateUnknownExtension(rawConfig.Fields, fmt.Sprintf("%s.%s", configPath, name)); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateUnknownExtension validates unknown extension configuration
func (l *YAMLConfigLoader) validateUnknownExtension(fields map[string]interface{}, configPath string) error {
	// Try to create and validate the unknown extension
	unknownExt := &extensions.UnknownExtension{}
	// Extract critical field from fields map, defaulting to false if not present
	critical := false
	if criticalVal, exists := fields["critical"]; exists {
		if criticalBool, ok := criticalVal.(bool); ok {
			critical = criticalBool
		}
	}
	if err := unknownExt.ParseFromYAML(critical, fields); err != nil {
		return fmt.Errorf("%w: %s: %v", domain.ErrValidation, configPath, err)
	}

	return nil
}

// ValidateCAConfig validates CA configuration against JSON schema.
func (l *YAMLConfigLoader) ValidateCAConfig(data []byte) error {
	return validateCAConfig(data)
}

// ValidateHostsConfig validates hosts configuration against JSON schema.
func (l *YAMLConfigLoader) ValidateHostsConfig(data []byte) error {
	return validateHostsConfig(data)
}
