package domain

import (
	"crypto/x509"
	"encoding/asn1"
)

// Extension represents a certificate extension that can be parsed from YAML
// and applied to an x509.Certificate template
type Extension interface {
	// ParseFromYAML parses extension configuration from generic YAML data
	ParseFromYAML(critical bool, data map[string]interface{}) error

	// ApplyToCertificate applies the extension to an x509.Certificate template
	ApplyToCertificate(cert *x509.Certificate) error

	// Name returns the extension name as used in YAML configuration
	Name() string

	// OID returns the extension's ASN.1 object identifier (empty for built-in extensions)
	OID() asn1.ObjectIdentifier
}

// ExtensionFactory creates and manages certificate extensions
type ExtensionFactory interface {
	// CreateExtension creates an extension by name, returns nil if unknown
	CreateExtension(name string) Extension

	// RegisterExtension registers a new extension type
	RegisterExtension(name string, creator func() Extension)

	// ListExtensions returns all registered extension names
	ListExtensions() []string

	// IsRegistered checks if an extension name is registered
	IsRegistered(name string) bool
}

// ExtensionsConfig represents the generic extensions configuration from YAML
type ExtensionsConfig map[string]ExtensionRawConfig

// ExtensionRawConfig represents raw extension configuration with critical flag
// and arbitrary fields that will be parsed by the specific extension implementation
type ExtensionRawConfig struct {
	Critical bool                   `yaml:"critical"`
	Fields   map[string]interface{} `yaml:",inline"`
}
