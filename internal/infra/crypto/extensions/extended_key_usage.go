package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// ExtendedKeyUsageExtension implements the X.509 Extended Key Usage extension (RFC 5280)
type ExtendedKeyUsageExtension struct {
	Critical           bool
	ServerAuth         bool     // x509.ExtKeyUsageServerAuth
	ClientAuth         bool     // x509.ExtKeyUsageClientAuth
	CodeSigning        bool     // x509.ExtKeyUsageCodeSigning
	EmailProtection    bool     // x509.ExtKeyUsageEmailProtection
	TimeStamping       bool     // x509.ExtKeyUsageTimeStamping
	OCSPSigning        bool     // x509.ExtKeyUsageOCSPSigning
	UnknownExtKeyUsage []string // Custom OIDs as strings
}

// Name returns the extension name as used in YAML configuration
func (e *ExtendedKeyUsageExtension) Name() string {
	return "extended_key_usage"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *ExtendedKeyUsageExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the extended_key_usage configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	server_auth: true/false (default: false)
//	client_auth: true/false (default: false)
//	code_signing: true/false (default: false)
//	email_protection: true/false (default: false)
//	time_stamping: true/false (default: false)
//	ocsp_signing: true/false (default: false)
//	unknown_ext_key_usage: []string (list of OID strings)
func (e *ExtendedKeyUsageExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical
	e.ServerAuth = parseFieldAs(data, "server_auth", false)
	e.ClientAuth = parseFieldAs(data, "client_auth", false)
	e.CodeSigning = parseFieldAs(data, "code_signing", false)
	e.EmailProtection = parseFieldAs(data, "email_protection", false)
	e.TimeStamping = parseFieldAs(data, "time_stamping", false)
	e.OCSPSigning = parseFieldAs(data, "ocsp_signing", false)

	// Parse unknown EKU OIDs
	e.UnknownExtKeyUsage = parseStringSlice(data, "unknown_ext_key_usage")

	// Validate OID format for unknown EKUs
	for _, oidStr := range e.UnknownExtKeyUsage {
		if err := validateOIDString(oidStr); err != nil {
			return fmt.Errorf("invalid OID in unknown_ext_key_usage: %s - %v", oidStr, err)
		}
	}

	return nil
}

// ApplyToCertificate applies the Extended Key Usage extension to an x509.Certificate template
func (e *ExtendedKeyUsageExtension) ApplyToCertificate(cert *x509.Certificate) error {
	var extKeyUsage []x509.ExtKeyUsage
	var unknownExtKeyUsage []asn1.ObjectIdentifier

	// Add standard EKUs
	if e.ServerAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if e.ClientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if e.CodeSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageCodeSigning)
	}
	if e.EmailProtection {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
	if e.TimeStamping {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageTimeStamping)
	}
	if e.OCSPSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}

	// Add unknown EKUs
	for _, oidStr := range e.UnknownExtKeyUsage {
		oid, err := parseOIDString(oidStr)
		if err != nil {
			return fmt.Errorf("failed to parse unknown EKU OID %s: %v", oidStr, err)
		}
		unknownExtKeyUsage = append(unknownExtKeyUsage, oid)
	}

	cert.ExtKeyUsage = extKeyUsage
	cert.UnknownExtKeyUsage = unknownExtKeyUsage

	return nil
}

// validateOIDString validates that a string represents a valid ASN.1 object identifier
func validateOIDString(oidStr string) error {
	parts := strings.Split(oidStr, ".")
	if len(parts) < 2 {
		return fmt.Errorf("OID must have at least 2 components")
	}

	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return fmt.Errorf("OID component %d is not a number: %s", i, part)
		}
		if num < 0 {
			return fmt.Errorf("OID component %d must be non-negative: %d", i, num)
		}
		// First component must be 0, 1, or 2
		if i == 0 && num > 2 {
			return fmt.Errorf("first OID component must be 0, 1, or 2: %d", num)
		}
		// Second component must be 0-39 if first is 0 or 1
		if i == 1 && len(parts) > 0 {
			firstNum, _ := strconv.Atoi(parts[0])
			if firstNum < 2 && num > 39 {
				return fmt.Errorf("second OID component must be 0-39 when first is %d: %d", firstNum, num)
			}
		}
	}

	return nil
}

// parseOIDString converts a string OID to asn1.ObjectIdentifier
func parseOIDString(oidStr string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))

	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component: %s", part)
		}
		oid[i] = num
	}

	return oid, nil
}
