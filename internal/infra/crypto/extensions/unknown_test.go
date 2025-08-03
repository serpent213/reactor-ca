//go:build !integration && !e2e

package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"testing"
)

func TestUnknownExtension_Name(t *testing.T) {
	ext := &UnknownExtension{OIDStr: "1.2.3.4"}
	if got := ext.Name(); got != "1.2.3.4" {
		t.Errorf("Name() = %q, want %q", got, "1.2.3.4")
	}
}

func TestUnknownExtension_OID(t *testing.T) {
	ext := &UnknownExtension{
		oid: asn1.ObjectIdentifier{1, 2, 3, 4},
	}
	expected := asn1.ObjectIdentifier{1, 2, 3, 4}
	got := ext.OID()
	if !got.Equal(expected) {
		t.Errorf("OID() = %v, want %v", got, expected)
	}
}

func TestUnknownExtension_ParseFromYAML(t *testing.T) {
	tests := []struct {
		name     string
		critical bool
		data     map[string]interface{}
		want     UnknownExtension
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid base64 encoding",
			critical: true,
			data: map[string]interface{}{
				"oid":    "1.2.3.4",
				"base64": "SGVsbG8gV29ybGQ=", // "Hello World"
			},
			want: UnknownExtension{
				Critical: true,
				OIDStr:   "1.2.3.4",
				oid:      asn1.ObjectIdentifier{1, 2, 3, 4},
				Value:    []byte("Hello World"),
			},
			wantErr: false,
		},
		{
			name:     "valid hex encoding",
			critical: false,
			data: map[string]interface{}{
				"oid": "1.3.6.1.4.1.12345.1",
				"hex": "48656c6c6f20576f726c64", // "Hello World"
			},
			want: UnknownExtension{
				Critical: false,
				OIDStr:   "1.3.6.1.4.1.12345.1",
				oid:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 1},
				Value:    []byte("Hello World"),
			},
			wantErr: false,
		},
		{
			name:     "valid ASN.1 string encoding",
			critical: true,
			data: map[string]interface{}{
				"oid": "2.5.29.32",
				"asn1": map[string]interface{}{
					"string": "Test String",
				},
			},
			want: UnknownExtension{
				Critical: true,
				OIDStr:   "2.5.29.32",
				oid:      asn1.ObjectIdentifier{2, 5, 29, 32},
			},
			wantErr: false,
		},
		{
			name:     "valid ASN.1 integer encoding",
			critical: false,
			data: map[string]interface{}{
				"oid": "1.2.3.4.5",
				"asn1": map[string]interface{}{
					"int": 42,
				},
			},
			want: UnknownExtension{
				Critical: false,
				OIDStr:   "1.2.3.4.5",
				oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			},
			wantErr: false,
		},
		{
			name:     "valid ASN.1 boolean encoding",
			critical: true,
			data: map[string]interface{}{
				"oid": "1.2.3.4.6",
				"asn1": map[string]interface{}{
					"bool": true,
				},
			},
			want: UnknownExtension{
				Critical: true,
				OIDStr:   "1.2.3.4.6",
				oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 6},
			},
			wantErr: false,
		},
		{
			name:     "valid ASN.1 OID encoding",
			critical: false,
			data: map[string]interface{}{
				"oid": "1.2.3.4.7",
				"asn1": map[string]interface{}{
					"oid": "1.2.840.113549.1.1.11",
				},
			},
			want: UnknownExtension{
				Critical: false,
				OIDStr:   "1.2.3.4.7",
				oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 7},
			},
			wantErr: false,
		},
		{
			name:     "missing OID field",
			critical: false,
			data: map[string]interface{}{
				"base64": "SGVsbG8=",
			},
			wantErr: true,
			errMsg:  "required field 'oid' is missing",
		},
		{
			name:     "OID not string",
			critical: false,
			data: map[string]interface{}{
				"oid":    123,
				"base64": "SGVsbG8=",
			},
			wantErr: true,
			errMsg:  "oid must be a string",
		},
		{
			name:     "invalid OID format",
			critical: false,
			data: map[string]interface{}{
				"oid":    "invalid.oid",
				"base64": "SGVsbG8=",
			},
			wantErr: true,
			errMsg:  "invalid OID",
		},
		{
			name:     "no value encoding specified",
			critical: false,
			data: map[string]interface{}{
				"oid": "1.2.3.4",
			},
			wantErr: true,
			errMsg:  "must specify exactly one value encoding",
		},
		{
			name:     "multiple value encodings specified",
			critical: false,
			data: map[string]interface{}{
				"oid":    "1.2.3.4",
				"base64": "SGVsbG8=",
				"hex":    "48656c6c6f",
			},
			wantErr: true,
			errMsg:  "specify exactly one value encoding",
		},
		{
			name:     "invalid base64 data",
			critical: false,
			data: map[string]interface{}{
				"oid":    "1.2.3.4",
				"base64": "invalid base64!!!",
			},
			wantErr: true,
			errMsg:  "failed to parse base64 value",
		},
		{
			name:     "invalid hex data",
			critical: false,
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"hex": "invalid hex",
			},
			wantErr: true,
			errMsg:  "failed to parse hex value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &UnknownExtension{}
			err := ext.ParseFromYAML(tt.critical, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFromYAML() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("ParseFromYAML() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseFromYAML() unexpected error: %v", err)
				return
			}

			if ext.Critical != tt.want.Critical {
				t.Errorf("Critical = %v, want %v", ext.Critical, tt.want.Critical)
			}

			if ext.OIDStr != tt.want.OIDStr {
				t.Errorf("OIDStr = %q, want %q", ext.OIDStr, tt.want.OIDStr)
			}

			if !ext.oid.Equal(tt.want.oid) {
				t.Errorf("oid = %v, want %v", ext.oid, tt.want.oid)
			}

			// For ASN.1 tests, we don't compare the raw Value bytes since they're encoded
			if tt.want.Value != nil && string(ext.Value) != string(tt.want.Value) {
				t.Errorf("Value = %v, want %v", ext.Value, tt.want.Value)
			}
		})
	}
}

func TestUnknownExtension_ApplyToCertificate(t *testing.T) {
	tests := []struct {
		name string
		ext  UnknownExtension
		want pkix.Extension
	}{
		{
			name: "critical extension",
			ext: UnknownExtension{
				Critical: true,
				oid:      asn1.ObjectIdentifier{1, 2, 3, 4},
				Value:    []byte("test data"),
			},
			want: pkix.Extension{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
				Critical: true,
				Value:    []byte("test data"),
			},
		},
		{
			name: "non-critical extension",
			ext: UnknownExtension{
				Critical: false,
				oid:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 1},
				Value:    []byte("another test"),
			},
			want: pkix.Extension{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 1},
				Critical: false,
				Value:    []byte("another test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			err := tt.ext.ApplyToCertificate(cert)

			if err != nil {
				t.Errorf("ApplyToCertificate() unexpected error: %v", err)
				return
			}

			if len(cert.ExtraExtensions) != 1 {
				t.Errorf("Expected 1 extra extension, got %d", len(cert.ExtraExtensions))
				return
			}

			got := cert.ExtraExtensions[0]
			if !got.Id.Equal(tt.want.Id) {
				t.Errorf("Extension Id = %v, want %v", got.Id, tt.want.Id)
			}

			if got.Critical != tt.want.Critical {
				t.Errorf("Extension Critical = %v, want %v", got.Critical, tt.want.Critical)
			}

			if string(got.Value) != string(tt.want.Value) {
				t.Errorf("Extension Value = %v, want %v", got.Value, tt.want.Value)
			}
		})
	}
}

func TestEncodeNativeASN1Value(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "string map",
			data: map[string]interface{}{
				"string": "Hello World",
			},
			wantErr: false,
		},
		{
			name: "integer map",
			data: map[string]interface{}{
				"int": 42,
			},
			wantErr: false,
		},
		{
			name: "boolean map",
			data: map[string]interface{}{
				"bool": true,
			},
			wantErr: false,
		},
		{
			name: "OID map",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
			},
			wantErr: false,
		},
		{
			name: "sequence array",
			data: []interface{}{
				map[string]interface{}{"string": "item1"},
				map[string]interface{}{"int": 123},
			},
			wantErr: false,
		},
		{
			name:    "invalid type",
			data:    "raw string",
			wantErr: true,
			errMsg:  "ASN.1 data must be a map or array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeNativeASN1Value(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("encodeNativeASN1Value() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("encodeNativeASN1Value() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("encodeNativeASN1Value() unexpected error: %v", err)
			}
		})
	}
}

func TestEncodeASN1Map(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "string type",
			data: map[string]interface{}{
				"string": "Test String",
			},
			wantErr: false,
		},
		{
			name: "int type - int value",
			data: map[string]interface{}{
				"int": 42,
			},
			wantErr: false,
		},
		{
			name: "int type - int64 value",
			data: map[string]interface{}{
				"int": int64(42),
			},
			wantErr: false,
		},
		{
			name: "int type - float64 value",
			data: map[string]interface{}{
				"int": float64(42),
			},
			wantErr: false,
		},
		{
			name: "int type - string value",
			data: map[string]interface{}{
				"int": "42",
			},
			wantErr: false,
		},
		{
			name: "bool type - bool value",
			data: map[string]interface{}{
				"bool": true,
			},
			wantErr: false,
		},
		{
			name: "bool type - string true",
			data: map[string]interface{}{
				"bool": "true",
			},
			wantErr: false,
		},
		{
			name: "bool type - string false",
			data: map[string]interface{}{
				"bool": "false",
			},
			wantErr: false,
		},
		{
			name: "oid type",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
			},
			wantErr: false,
		},
		{
			name: "sequence type",
			data: map[string]interface{}{
				"sequence": []interface{}{
					map[string]interface{}{"string": "item1"},
					map[string]interface{}{"int": 123},
				},
			},
			wantErr: false,
		},
		{
			name: "octetstring type",
			data: map[string]interface{}{
				"octetstring": map[string]interface{}{
					"string": "wrapped data",
				},
			},
			wantErr: false,
		},
		{
			name: "bitstring type - binary string",
			data: map[string]interface{}{
				"bitstring": "10110001",
			},
			wantErr: false,
		},
		{
			name: "bitstring type - bit positions array",
			data: map[string]interface{}{
				"bitstring": []interface{}{0, 2, 3, 7},
			},
			wantErr: false,
		},
		{
			name:    "empty map",
			data:    map[string]interface{}{},
			wantErr: true,
			errMsg:  "ASN.1 map must have exactly one key-value pair, got 0",
		},
		{
			name: "multiple keys",
			data: map[string]interface{}{
				"string": "test",
				"int":    42,
			},
			wantErr: true,
			errMsg:  "ASN.1 map must have exactly one key-value pair, got 2",
		},
		{
			name: "string type - non-string value",
			data: map[string]interface{}{
				"string": 123,
			},
			wantErr: true,
			errMsg:  "string value must be a string",
		},
		{
			name: "int type - invalid string",
			data: map[string]interface{}{
				"int": "not a number",
			},
			wantErr: true,
			errMsg:  "invalid integer value",
		},
		{
			name: "int type - invalid type",
			data: map[string]interface{}{
				"int": []int{1, 2, 3},
			},
			wantErr: true,
			errMsg:  "int value must be a number or string",
		},
		{
			name: "bool type - invalid string",
			data: map[string]interface{}{
				"bool": "maybe",
			},
			wantErr: true,
			errMsg:  "boolean value must be 'true' or 'false'",
		},
		{
			name: "bool type - invalid type",
			data: map[string]interface{}{
				"bool": 123,
			},
			wantErr: true,
			errMsg:  "bool value must be a boolean or string",
		},
		{
			name: "oid type - non-string value",
			data: map[string]interface{}{
				"oid": 123,
			},
			wantErr: true,
			errMsg:  "oid value must be a string",
		},
		{
			name: "oid type - invalid OID",
			data: map[string]interface{}{
				"oid": "invalid.oid",
			},
			wantErr: true,
			errMsg:  "invalid OID value",
		},
		{
			name: "sequence type - non-array value",
			data: map[string]interface{}{
				"sequence": "not an array",
			},
			wantErr: true,
			errMsg:  "sequence value must be an array",
		},
		{
			name:    "unsupported type",
			data:    map[string]interface{}{"unknown": "value"},
			wantErr: true,
			errMsg:  "unsupported ASN.1 type: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeASN1Map(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("encodeASN1Map() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("encodeASN1Map() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("encodeASN1Map() unexpected error: %v", err)
			}
		})
	}
}

func TestEncodeNativeBitString(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid binary string",
			value:   "10110001",
			wantErr: false,
		},
		{
			name:    "empty binary string",
			value:   "",
			wantErr: false,
		},
		{
			name:    "valid bit positions array - integers",
			value:   []interface{}{0, 2, 3, 7},
			wantErr: false,
		},
		{
			name:    "valid bit positions array - floats",
			value:   []interface{}{float64(0), float64(2), float64(3)},
			wantErr: false,
		},
		{
			name:    "empty bit positions array",
			value:   []interface{}{},
			wantErr: false,
		},
		{
			name:    "invalid binary string - contains invalid chars",
			value:   "1011x001",
			wantErr: true,
			errMsg:  "invalid binary string",
		},
		{
			name:    "bit positions array - invalid type",
			value:   []interface{}{"not a number"},
			wantErr: true,
			errMsg:  "bit position must be an integer",
		},
		{
			name:    "bit positions array - negative position",
			value:   []interface{}{-1, 2, 3},
			wantErr: true,
			errMsg:  "bit position cannot be negative",
		},
		{
			name:    "invalid value type",
			value:   123,
			wantErr: true,
			errMsg:  "bitstring value must be a string or array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeNativeBitString(tt.value)

			if tt.wantErr {
				if err == nil {
					t.Errorf("encodeNativeBitString() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("encodeNativeBitString() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("encodeNativeBitString() unexpected error: %v", err)
			}
		})
	}
}

func TestIsValidBinaryString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "valid binary string",
			s:    "10110001",
			want: true,
		},
		{
			name: "empty string",
			s:    "",
			want: true,
		},
		{
			name: "only zeros",
			s:    "0000",
			want: true,
		},
		{
			name: "only ones",
			s:    "1111",
			want: true,
		},
		{
			name: "contains invalid character",
			s:    "1011x001",
			want: false,
		},
		{
			name: "contains space",
			s:    "101 001",
			want: false,
		},
		{
			name: "contains digit 2",
			s:    "1012001",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidBinaryString(tt.s)
			if got != tt.want {
				t.Errorf("isValidBinaryString(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestUnknownExtension_ParseFromYAML_ASN1_ComplexTypes(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "ASN.1 sequence with mixed types",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"sequence": []interface{}{
						map[string]interface{}{"string": "test"},
						map[string]interface{}{"int": 42},
						map[string]interface{}{"bool": true},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ASN.1 octet string wrapping another type",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"octetstring": map[string]interface{}{
						"string": "wrapped content",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ASN.1 nested sequence",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": []interface{}{
					map[string]interface{}{"string": "outer"},
					[]interface{}{
						map[string]interface{}{"string": "inner1"},
						map[string]interface{}{"int": 123},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ASN.1 bitstring with binary string format",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"bitstring": "10110001",
				},
			},
			wantErr: false,
		},
		{
			name: "ASN.1 bitstring with bit positions format",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"bitstring": []interface{}{0, 2, 5, 7},
				},
			},
			wantErr: false,
		},
		{
			name: "ASN.1 failed encoding",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"sequence": []interface{}{
						"invalid item", // This should cause encoding to fail
					},
				},
			},
			wantErr: true,
			errMsg:  "failed to parse ASN.1 value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &UnknownExtension{}
			err := ext.ParseFromYAML(false, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFromYAML() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("ParseFromYAML() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseFromYAML() unexpected error: %v", err)
				return
			}

			// Basic validation that parsing succeeded
			if ext.OIDStr == "" {
				t.Error("OIDStr should not be empty after successful parsing")
			}
			if len(ext.Value) == 0 {
				t.Error("Value should not be empty after successful ASN.1 encoding")
			}
		})
	}
}

func TestUnknownExtension_RoundTrip(t *testing.T) {
	// Test that we can parse YAML, apply to certificate, and verify the extension exists
	testData := map[string]interface{}{
		"oid":    "1.3.6.1.4.1.12345.999",
		"base64": base64.StdEncoding.EncodeToString([]byte("Round trip test data")),
	}

	ext := &UnknownExtension{}
	err := ext.ParseFromYAML(true, testData)
	if err != nil {
		t.Fatalf("ParseFromYAML() failed: %v", err)
	}

	cert := &x509.Certificate{}
	err = ext.ApplyToCertificate(cert)
	if err != nil {
		t.Fatalf("ApplyToCertificate() failed: %v", err)
	}

	// Verify the extension was added
	if len(cert.ExtraExtensions) != 1 {
		t.Fatalf("Expected 1 extension, got %d", len(cert.ExtraExtensions))
	}

	gotExt := cert.ExtraExtensions[0]
	expectedOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 999}

	if !gotExt.Id.Equal(expectedOID) {
		t.Errorf("Extension OID = %v, want %v", gotExt.Id, expectedOID)
	}

	if !gotExt.Critical {
		t.Error("Extension should be critical")
	}

	if string(gotExt.Value) != "Round trip test data" {
		t.Errorf("Extension value = %q, want %q", string(gotExt.Value), "Round trip test data")
	}
}

func TestUnknownExtension_EdgeCases(t *testing.T) {
	// Test edge cases that might not be covered in the main tests
	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "ASN.1 octet string with encoding failure",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"octetstring": "invalid raw string", // Should cause encoding failure
				},
			},
			wantErr: true,
			errMsg:  "failed to encode octet string content",
		},
		{
			name: "ASN.1 sequence with encoding failure",
			data: map[string]interface{}{
				"oid": "1.2.3.4",
				"asn1": map[string]interface{}{
					"sequence": []interface{}{
						"invalid raw string", // Should cause encoding failure
					},
				},
			},
			wantErr: true,
			errMsg:  "ASN.1 data must be a map or array",
		},
		{
			name: "OID parsing failure after validation passes",
			data: map[string]interface{}{
				"oid":    "1.2.3.4", // This will pass validation but might fail parsing in edge cases
				"base64": "dGVzdA==",
			},
			wantErr: false, // This should actually succeed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &UnknownExtension{}
			err := ext.ParseFromYAML(false, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFromYAML() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("ParseFromYAML() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseFromYAML() unexpected error: %v", err)
			}
		})
	}
}

func TestEncodeASN1Map_AdditionalEdgeCases(t *testing.T) {
	// Test more specific edge cases for better coverage
	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "failed OID parsing in oid type",
			data: map[string]interface{}{
				"oid": "1.2.3", // Valid format but could fail in parsing step
			},
			wantErr: false, // Actually this should work
		},
		{
			name: "sequence with nested encoding failure",
			data: map[string]interface{}{
				"sequence": []interface{}{
					map[string]interface{}{"string": "valid"},
					"invalid item", // This should cause recursive encoding to fail
				},
			},
			wantErr: true,
			errMsg:  "ASN.1 data must be a map or array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeASN1Map(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("encodeASN1Map() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("encodeASN1Map() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("encodeASN1Map() unexpected error: %v", err)
			}
		})
	}
}

func TestEncodeNativeASN1Value_ArrayEdgeCases(t *testing.T) {
	// Test array handling in encodeNativeASN1Value
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "array with encoding failure",
			data: []interface{}{
				"invalid item", // Should cause encoding failure
			},
			wantErr: true,
			errMsg:  "ASN.1 data must be a map or array",
		},
		{
			name:    "empty array",
			data:    []interface{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeNativeASN1Value(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("encodeNativeASN1Value() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("encodeNativeASN1Value() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("encodeNativeASN1Value() unexpected error: %v", err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
