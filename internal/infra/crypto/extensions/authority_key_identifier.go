package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

// AuthorityKeyIdentifierExtension implements the X.509 Authority Key Identifier extension (RFC 5280)
type AuthorityKeyIdentifierExtension struct {
	Critical     bool
	KeyID        []byte // Authority key identifier
	Issuer       []byte // Authority cert issuer (rarely used)
	SerialNumber []byte // Authority cert serial number (rarely used)
}

// Name returns the extension name as used in YAML configuration
func (e *AuthorityKeyIdentifierExtension) Name() string {
	return "authority_key_identifier"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *AuthorityKeyIdentifierExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the authority_key_identifier configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	key_id: string with hex: prefix for key identifier
//	issuer: string with hex: prefix for issuer (rarely used)
//	serial_number: string with hex: prefix for serial number (rarely used)
func (e *AuthorityKeyIdentifierExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical

	// Parse key_id
	if keyIDVal, exists := data["key_id"]; exists {
		keyIDStr, ok := keyIDVal.(string)
		if !ok {
			return fmt.Errorf("key_id must be a string")
		}

		if strings.HasPrefix(keyIDStr, "hex:") {
			hexStr := strings.TrimPrefix(keyIDStr, "hex:")
			bytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("invalid hex encoding in key_id: %v", err)
			}
			e.KeyID = bytes
		} else {
			return fmt.Errorf("key_id must be prefixed with 'hex:' for hex encoding")
		}
	}

	// Parse issuer (optional)
	if issuerVal, exists := data["issuer"]; exists {
		issuerStr, ok := issuerVal.(string)
		if !ok {
			return fmt.Errorf("issuer must be a string")
		}

		if strings.HasPrefix(issuerStr, "hex:") {
			hexStr := strings.TrimPrefix(issuerStr, "hex:")
			bytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("invalid hex encoding in issuer: %v", err)
			}
			e.Issuer = bytes
		} else {
			return fmt.Errorf("issuer must be prefixed with 'hex:' for hex encoding")
		}
	}

	// Parse serial_number (optional)
	if serialVal, exists := data["serial_number"]; exists {
		serialStr, ok := serialVal.(string)
		if !ok {
			return fmt.Errorf("serial_number must be a string")
		}

		if strings.HasPrefix(serialStr, "hex:") {
			hexStr := strings.TrimPrefix(serialStr, "hex:")
			bytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("invalid hex encoding in serial_number: %v", err)
			}
			e.SerialNumber = bytes
		} else {
			return fmt.Errorf("serial_number must be prefixed with 'hex:' for hex encoding")
		}
	}

	return nil
}

// ApplyToCertificate applies the Authority Key Identifier extension to an x509.Certificate template
func (e *AuthorityKeyIdentifierExtension) ApplyToCertificate(cert *x509.Certificate) error {
	// Set the Authority Key Identifier
	if len(e.KeyID) > 0 {
		cert.AuthorityKeyId = e.KeyID
	}

	// Note: Go's x509 package doesn't directly support setting Issuer and SerialNumber
	// in the AuthorityKeyIdentifier extension through the Certificate struct.
	// These would need to be handled via ExtraExtensions if needed.
	// For most use cases, KeyID is sufficient.

	if len(e.Issuer) > 0 || len(e.SerialNumber) > 0 {
		return fmt.Errorf("issuer and serial_number fields in authority_key_identifier are not yet supported - only key_id is supported")
	}

	return nil
}
