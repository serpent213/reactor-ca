package extensions

import (
	"crypto/x509"
	"encoding/asn1"
)

// BasicConstraintsExtension implements the X.509 Basic Constraints extension (RFC 5280)
type BasicConstraintsExtension struct {
	Critical       bool
	CA             bool
	PathLength     *int // MaxPathLen field - nil means no constraint
	PathLengthZero bool // MaxPathLenZero field - explicit zero vs unset
}

// Name returns the extension name as used in YAML configuration
func (e *BasicConstraintsExtension) Name() string {
	return "basic_constraints"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *BasicConstraintsExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the basic_constraints configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	ca: true/false (default: false)
//	path_length: integer or null (default: null, no constraint)
//	           when set to 0, automatically enables zero constraint behavior
func (e *BasicConstraintsExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical
	e.CA = parseFieldAs(data, "ca", false)
	e.PathLength = parseFieldAsPtr[int](data, "path_length")

	// Auto-detect PathLengthZero when path_length is explicitly set to 0
	if e.PathLength != nil && *e.PathLength == 0 {
		e.PathLengthZero = true
	}

	return nil
}

// ApplyToCertificate applies the Basic Constraints extension to an x509.Certificate template
func (e *BasicConstraintsExtension) ApplyToCertificate(cert *x509.Certificate) error {
	cert.IsCA = e.CA
	cert.BasicConstraintsValid = true

	if e.PathLength != nil {
		cert.MaxPathLen = *e.PathLength
		cert.MaxPathLenZero = e.PathLengthZero
	}

	return nil
}
