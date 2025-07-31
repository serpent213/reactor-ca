package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

// SubjectKeyIdentifierExtension implements the X.509 Subject Key Identifier extension (RFC 5280)
type SubjectKeyIdentifierExtension struct {
	Critical    bool
	Method      string // "hash" or "manual"
	ManualValue []byte // Raw bytes for manual specification
}

// Name returns the extension name as used in YAML configuration
func (e *SubjectKeyIdentifierExtension) Name() string {
	return "subject_key_identifier"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *SubjectKeyIdentifierExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the subject_key_identifier configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	method: "hash" or "manual" (default: "hash")
//	manual_value: string with hex: prefix for manual specification
func (e *SubjectKeyIdentifierExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical
	e.Method = parseFieldAs(data, "method", "hash")

	// Validate method
	if e.Method != "hash" && e.Method != "manual" {
		return fmt.Errorf("method must be 'hash' or 'manual', got: %s", e.Method)
	}

	// Parse manual value if specified
	if manualVal, exists := data["manual_value"]; exists {
		if e.Method != "manual" {
			return fmt.Errorf("manual_value can only be specified when method is 'manual'")
		}

		valStr, ok := manualVal.(string)
		if !ok {
			return fmt.Errorf("manual_value must be a string")
		}

		// Parse hex-encoded value
		if strings.HasPrefix(valStr, "hex:") {
			hexStr := strings.TrimPrefix(valStr, "hex:")
			bytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("invalid hex encoding in manual_value: %v", err)
			}
			e.ManualValue = bytes
		} else {
			return fmt.Errorf("manual_value must be prefixed with 'hex:' for hex encoding")
		}
	} else if e.Method == "manual" {
		return fmt.Errorf("manual_value is required when method is 'manual'")
	}

	return nil
}

// ApplyToCertificate applies the Subject Key Identifier extension to an x509.Certificate template
// Note: For "hash" method, the actual SKI will be computed by Go's x509 package during certificate creation
func (e *SubjectKeyIdentifierExtension) ApplyToCertificate(cert *x509.Certificate) error {
	switch e.Method {
	case "hash":
		// The x509 package will automatically generate the SKI from the public key hash
		// We just need to ensure it's enabled (this is actually the default behavior)
		// No explicit action needed - Go's x509 handles this automatically

	case "manual":
		// Set the explicit Subject Key Identifier
		cert.SubjectKeyId = e.ManualValue

	default:
		return fmt.Errorf("unsupported SKI method: %s", e.Method)
	}

	return nil
}
