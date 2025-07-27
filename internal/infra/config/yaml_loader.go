package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
	"reactor.de/reactor-ca/internal/domain"
)

// YAMLConfigLoader implements the domain.ConfigLoader interface for YAML files.
type YAMLConfigLoader struct {
	configPath string
}

// NewYAMLConfigLoader creates a new config loader.
func NewYAMLConfigLoader(configPath string) *YAMLConfigLoader {
	return &YAMLConfigLoader{configPath: configPath}
}

// LoadCA loads the CA configuration from ca.yaml.
func (l *YAMLConfigLoader) LoadCA() (*domain.CAConfig, error) {
	path := filepath.Join(l.configPath, "ca.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ca.yaml: %w", err)
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

	return &cfg, nil
}

// LoadHosts loads the hosts configuration from hosts.yaml.
func (l *YAMLConfigLoader) LoadHosts() (*domain.HostsConfig, error) {
	path := filepath.Join(l.configPath, "hosts.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read hosts.yaml: %w", err)
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
	}

	return &cfg, nil
}
