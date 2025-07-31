package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// UnknownExtension handles custom extensions specified by OID
type UnknownExtension struct {
	Critical bool
	OIDStr   string
	oid      asn1.ObjectIdentifier
	Value    []byte
}

// Name returns the extension name (which is the OID string for unknown extensions)
func (e *UnknownExtension) Name() string {
	return e.OIDStr
}

// OID returns the extension's ASN.1 object identifier
func (e *UnknownExtension) OID() asn1.ObjectIdentifier {
	return e.oid
}

// ParseFromYAML parses an unknown extension configuration from YAML
// Required fields:
//
//	critical: true/false (required)
//	oid: string (required, ASN.1 object identifier)
//	value: string (required, encoded value with prefix)
//
// Supported value encodings:
//
//	base64:encoded_data - Base64 encoded binary data
//	hex:hexstring - Hex encoded binary data
//	asn1:type:value - ASN.1 encoded value (limited support)
func (e *UnknownExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical

	// Parse OID
	if err := validateRequiredField(data, "oid"); err != nil {
		return err
	}

	oidStr, ok := data["oid"].(string)
	if !ok {
		return fmt.Errorf("oid must be a string")
	}

	if err := validateOIDString(oidStr); err != nil {
		return fmt.Errorf("invalid OID: %v", err)
	}

	oid, err := parseOIDString(oidStr)
	if err != nil {
		return fmt.Errorf("failed to parse OID: %v", err)
	}

	e.OIDStr = oidStr
	e.oid = oid

	// Parse value
	if err := validateRequiredField(data, "value"); err != nil {
		return err
	}

	valueStr, ok := data["value"].(string)
	if !ok {
		return fmt.Errorf("value must be a string")
	}

	value, err := parseExtensionValue(valueStr)
	if err != nil {
		return fmt.Errorf("failed to parse extension value: %v", err)
	}

	e.Value = value
	return nil
}

// ApplyToCertificate applies the unknown extension to an x509.Certificate template
func (e *UnknownExtension) ApplyToCertificate(cert *x509.Certificate) error {
	extension := pkix.Extension{
		Id:       e.oid,
		Critical: e.Critical,
		Value:    e.Value,
	}

	cert.ExtraExtensions = append(cert.ExtraExtensions, extension)
	return nil
}

// parseExtensionValue parses encoded extension values
func parseExtensionValue(valueStr string) ([]byte, error) {
	if strings.HasPrefix(valueStr, "base64:") {
		// Base64 encoded data
		encodedData := strings.TrimPrefix(valueStr, "base64:")
		return base64.StdEncoding.DecodeString(encodedData)

	} else if strings.HasPrefix(valueStr, "hex:") {
		// Hex encoded data
		hexData := strings.TrimPrefix(valueStr, "hex:")
		return hex.DecodeString(hexData)

	} else if strings.HasPrefix(valueStr, "asn1:") {
		// ASN.1 encoded data with type hints
		return parseASN1Value(valueStr)

	} else {
		return nil, fmt.Errorf("value must be prefixed with 'base64:', 'hex:', or 'asn1:'")
	}
}

// parseASN1Value provides basic ASN.1 encoding for simple types
// Format: asn1:type:value
// Supported types: string, int, bool, oid
func parseASN1Value(valueStr string) ([]byte, error) {
	parts := strings.SplitN(valueStr, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("asn1 value format must be 'asn1:type:value'")
	}

	asn1Type := parts[1]
	value := parts[2]

	switch asn1Type {
	case "string":
		// ASN.1 UTF8String
		return asn1.Marshal(value)

	case "int":
		// Parse integer and encode as ASN.1 INTEGER
		var intVal int64
		if _, err := fmt.Sscanf(value, "%d", &intVal); err != nil {
			return nil, fmt.Errorf("invalid integer value: %s", value)
		}
		return asn1.Marshal(intVal)

	case "bool":
		// ASN.1 BOOLEAN
		var boolVal bool
		if value == "true" {
			boolVal = true
		} else if value == "false" {
			boolVal = false
		} else {
			return nil, fmt.Errorf("boolean value must be 'true' or 'false': %s", value)
		}
		return asn1.Marshal(boolVal)

	case "oid":
		// ASN.1 OBJECT IDENTIFIER
		if err := validateOIDString(value); err != nil {
			return nil, fmt.Errorf("invalid OID value: %v", err)
		}
		oid, err := parseOIDString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OID value: %v", err)
		}
		return asn1.Marshal(oid)

	default:
		return nil, fmt.Errorf("unsupported ASN.1 type: %s (supported: string, int, bool, oid)", asn1Type)
	}
}
