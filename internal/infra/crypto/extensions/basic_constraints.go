package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
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
//	path_length_zero: true/false (default: false, explicit zero handling)
func (e *BasicConstraintsExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical
	e.CA = parseFieldAs(data, "ca", false)
	e.PathLength = parseFieldAsPtr[int](data, "path_length")
	e.PathLengthZero = parseFieldAs(data, "path_length_zero", false)

	// Validate path_length_zero usage
	if e.PathLengthZero && e.PathLength != nil && *e.PathLength != 0 {
		return fmt.Errorf("path_length_zero can only be true when path_length is 0 or unset")
	}

	// If path_length_zero is true, set path_length to 0
	if e.PathLengthZero {
		zero := 0
		e.PathLength = &zero
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
