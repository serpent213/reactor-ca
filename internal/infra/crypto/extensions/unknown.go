package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
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
//
// Value encoding (specify exactly one):
//
//	hex: "deadbeef" - Hex encoded binary data
//	base64: "SGVsbG8=" - Base64 encoded binary data
//	asn1: <structure> - Native YAML ASN.1 structure
//
// ASN.1 Structure Examples:
//
//	asn1:
//	  string: "text" - UTF8 string
//	  int: 123 - Integer value
//	  bool: true - Boolean value
//	  oid: "1.2.3.4" - Object identifier
//	  sequence:
//	    - string: "foo"
//	    - int: 64
//	  octetstring:
//	    string: "wrapped data"
//	  bitstring: "10110000" - Binary string
//	  bitstring: [0,2,3] - Bit positions
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

	// Parse value using discriminated union approach
	var value []byte
	valueFieldCount := 0

	if asn1Data, ok := data["asn1"]; ok {
		var err error
		value, err = encodeNativeASN1Value(asn1Data)
		if err != nil {
			return fmt.Errorf("failed to parse ASN.1 value: %v", err)
		}
		valueFieldCount++
	}
	if hexData, ok := data["hex"].(string); ok {
		if valueFieldCount > 0 {
			return fmt.Errorf("specify exactly one value encoding: asn1, hex, or base64")
		}
		var err error
		value, err = hex.DecodeString(hexData)
		if err != nil {
			return fmt.Errorf("failed to parse hex value: %v", err)
		}
		valueFieldCount++
	}
	if b64Data, ok := data["base64"].(string); ok {
		if valueFieldCount > 0 {
			return fmt.Errorf("specify exactly one value encoding: asn1, hex, or base64")
		}
		var err error
		value, err = base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			return fmt.Errorf("failed to parse base64 value: %v", err)
		}
		valueFieldCount++
	}

	if valueFieldCount == 0 {
		return fmt.Errorf("must specify exactly one value encoding: asn1, hex, or base64")
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

// encodeNativeASN1Value recursively encodes native YAML ASN.1 structures
func encodeNativeASN1Value(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case map[string]interface{}:
		return encodeASN1Map(v)
	case []interface{}:
		// Array of ASN.1 values - encode as SEQUENCE
		var encodedValues [][]byte
		for _, item := range v {
			encoded, err := encodeNativeASN1Value(item)
			if err != nil {
				return nil, err
			}
			encodedValues = append(encodedValues, encoded)
		}
		return asn1.Marshal(encodedValues)
	default:
		return nil, fmt.Errorf("ASN.1 data must be a map or array, got %T", data)
	}
}

// encodeASN1Map encodes a single ASN.1 type from YAML map
func encodeASN1Map(data map[string]interface{}) ([]byte, error) {
	if len(data) != 1 {
		return nil, fmt.Errorf("ASN.1 map must have exactly one key-value pair, got %d", len(data))
	}

	for asn1Type, value := range data {
		switch asn1Type {
		case "string":
			str, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("string value must be a string, got %T", value)
			}
			return asn1.Marshal(str)

		case "int":
			var intVal int64
			switch v := value.(type) {
			case int:
				intVal = int64(v)
			case int64:
				intVal = v
			case float64:
				intVal = int64(v)
			case string:
				var err error
				intVal, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid integer value: %v", err)
				}
			default:
				return nil, fmt.Errorf("int value must be a number or string, got %T", value)
			}
			return asn1.Marshal(intVal)

		case "bool":
			var boolVal bool
			switch v := value.(type) {
			case bool:
				boolVal = v
			case string:
				if v == "true" {
					boolVal = true
				} else if v == "false" {
					boolVal = false
				} else {
					return nil, fmt.Errorf("boolean value must be 'true' or 'false': %s", v)
				}
			default:
				return nil, fmt.Errorf("bool value must be a boolean or string, got %T", value)
			}
			return asn1.Marshal(boolVal)

		case "oid":
			oidStr, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("oid value must be a string, got %T", value)
			}
			if err := validateOIDString(oidStr); err != nil {
				return nil, fmt.Errorf("invalid OID value: %v", err)
			}
			oid, err := parseOIDString(oidStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse OID value: %v", err)
			}
			return asn1.Marshal(oid)

		case "sequence":
			values, ok := value.([]interface{})
			if !ok {
				return nil, fmt.Errorf("sequence value must be an array, got %T", value)
			}
			var encodedValues [][]byte
			for _, v := range values {
				encoded, err := encodeNativeASN1Value(v)
				if err != nil {
					return nil, err
				}
				encodedValues = append(encodedValues, encoded)
			}
			return asn1.Marshal(encodedValues)

		case "octetstring":
			// OCTET STRING wraps other ASN.1 data
			innerData, err := encodeNativeASN1Value(value)
			if err != nil {
				return nil, fmt.Errorf("failed to encode octet string content: %v", err)
			}
			return asn1.Marshal(innerData)

		case "bitstring":
			return encodeNativeBitString(value)

		default:
			return nil, fmt.Errorf("unsupported ASN.1 type: %s (supported: string, int, bool, oid, sequence, octetstring, bitstring)", asn1Type)
		}
	}
	return nil, fmt.Errorf("internal error: unreachable code")
}

// encodeNativeBitString handles BIT STRING values from native YAML
func encodeNativeBitString(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case string:
		// Binary string format: "10110001"
		if !isValidBinaryString(v) {
			return nil, fmt.Errorf("invalid binary string: %s (must contain only 0 and 1)", v)
		}
		if len(v) == 0 {
			return asn1.Marshal(asn1.BitString{})
		}

		// Convert binary string to bytes
		bitLen := len(v)
		byteLen := (bitLen + 7) / 8
		bits := make([]byte, byteLen)

		for i, char := range v {
			if char == '1' {
				byteIndex := i / 8
				bitIndex := 7 - (i % 8) // MSB first
				bits[byteIndex] |= 1 << bitIndex
			}
		}

		return asn1.Marshal(asn1.BitString{
			Bytes:     bits,
			BitLength: bitLen,
		})

	case []interface{}:
		// Array format: [0,2,3,7] - bit positions
		if len(v) == 0 {
			return asn1.Marshal(asn1.BitString{})
		}

		var positions []int
		for _, pos := range v {
			switch p := pos.(type) {
			case int:
				positions = append(positions, p)
			case float64:
				positions = append(positions, int(p))
			default:
				return nil, fmt.Errorf("bit position must be an integer, got %T", pos)
			}
		}

		// Find maximum bit position to determine byte length
		maxBit := 0
		for _, pos := range positions {
			if pos < 0 {
				return nil, fmt.Errorf("bit position cannot be negative: %d", pos)
			}
			if pos > maxBit {
				maxBit = pos
			}
		}

		// Create byte array with enough space
		byteLen := (maxBit / 8) + 1
		bits := make([]byte, byteLen)

		// Set the specified bit positions
		for _, pos := range positions {
			byteIndex := pos / 8
			bitIndex := 7 - (pos % 8) // MSB first
			bits[byteIndex] |= 1 << bitIndex
		}

		return asn1.Marshal(asn1.BitString{
			Bytes:     bits,
			BitLength: maxBit + 1,
		})

	default:
		return nil, fmt.Errorf("bitstring value must be a string or array, got %T", value)
	}
}

// isValidBinaryString checks if a string contains only 0 and 1
func isValidBinaryString(s string) bool {
	for _, char := range s {
		if char != '0' && char != '1' {
			return false
		}
	}
	return true
}
