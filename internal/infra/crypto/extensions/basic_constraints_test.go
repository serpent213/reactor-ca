//go:build !integration && !e2e

package extensions

import (
	"crypto/x509"
	"testing"
)

func TestBasicConstraintsExtension_ParseFromYAML(t *testing.T) {
	tests := []struct {
		name     string
		critical bool
		data     map[string]interface{}
		want     BasicConstraintsExtension
		wantErr  bool
	}{
		{
			name:     "automatic path_length_zero when path_length is 0",
			critical: true,
			data: map[string]interface{}{
				"ca":          true,
				"path_length": 0,
			},
			want: BasicConstraintsExtension{
				Critical:       true,
				CA:             true,
				PathLength:     intPtr(0),
				PathLengthZero: true, // Should be auto-set
			},
			wantErr: false,
		},
		{
			name:     "no auto-inference when path_length is null",
			critical: false,
			data: map[string]interface{}{
				"ca": false,
			},
			want: BasicConstraintsExtension{
				Critical:       false,
				CA:             false,
				PathLength:     nil,
				PathLengthZero: false,
			},
			wantErr: false,
		},
		{
			name:     "no auto-inference when path_length is greater than 0",
			critical: true,
			data: map[string]interface{}{
				"ca":          true,
				"path_length": 2,
			},
			want: BasicConstraintsExtension{
				Critical:       true,
				CA:             true,
				PathLength:     intPtr(2),
				PathLengthZero: false,
			},
			wantErr: false,
		},
		{
			name:     "minimal configuration with defaults",
			critical: false,
			data:     map[string]interface{}{},
			want: BasicConstraintsExtension{
				Critical:       false,
				CA:             false,
				PathLength:     nil,
				PathLengthZero: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &BasicConstraintsExtension{}
			err := ext.ParseFromYAML(tt.critical, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFromYAML() expected error, got nil")
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

			if ext.CA != tt.want.CA {
				t.Errorf("CA = %v, want %v", ext.CA, tt.want.CA)
			}

			if !intPtrEqual(ext.PathLength, tt.want.PathLength) {
				t.Errorf("PathLength = %v, want %v", ext.PathLength, tt.want.PathLength)
			}

			if ext.PathLengthZero != tt.want.PathLengthZero {
				t.Errorf("PathLengthZero = %v, want %v", ext.PathLengthZero, tt.want.PathLengthZero)
			}
		})
	}
}

func TestBasicConstraintsExtension_ApplyToCertificate(t *testing.T) {
	tests := []struct {
		name string
		ext  BasicConstraintsExtension
		want x509.Certificate
	}{
		{
			name: "CA with path length constraint",
			ext: BasicConstraintsExtension{
				Critical:       true,
				CA:             true,
				PathLength:     intPtr(2),
				PathLengthZero: false,
			},
			want: x509.Certificate{
				IsCA:                  true,
				BasicConstraintsValid: true,
				MaxPathLen:            2,
				MaxPathLenZero:        false,
			},
		},
		{
			name: "CA with zero path length constraint",
			ext: BasicConstraintsExtension{
				Critical:       true,
				CA:             true,
				PathLength:     intPtr(0),
				PathLengthZero: true,
			},
			want: x509.Certificate{
				IsCA:                  true,
				BasicConstraintsValid: true,
				MaxPathLen:            0,
				MaxPathLenZero:        true,
			},
		},
		{
			name: "non-CA certificate",
			ext: BasicConstraintsExtension{
				Critical:       false,
				CA:             false,
				PathLength:     nil,
				PathLengthZero: false,
			},
			want: x509.Certificate{
				IsCA:                  false,
				BasicConstraintsValid: true,
				MaxPathLen:            0,
				MaxPathLenZero:        false,
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

			if cert.IsCA != tt.want.IsCA {
				t.Errorf("IsCA = %v, want %v", cert.IsCA, tt.want.IsCA)
			}

			if cert.BasicConstraintsValid != tt.want.BasicConstraintsValid {
				t.Errorf("BasicConstraintsValid = %v, want %v", cert.BasicConstraintsValid, tt.want.BasicConstraintsValid)
			}

			if tt.ext.PathLength != nil {
				if cert.MaxPathLen != tt.want.MaxPathLen {
					t.Errorf("MaxPathLen = %v, want %v", cert.MaxPathLen, tt.want.MaxPathLen)
				}

				if cert.MaxPathLenZero != tt.want.MaxPathLenZero {
					t.Errorf("MaxPathLenZero = %v, want %v", cert.MaxPathLenZero, tt.want.MaxPathLenZero)
				}
			}
		})
	}
}

func TestBasicConstraintsExtension_Name(t *testing.T) {
	ext := &BasicConstraintsExtension{}
	if got := ext.Name(); got != "basic_constraints" {
		t.Errorf("Name() = %v, want %v", got, "basic_constraints")
	}
}

func TestBasicConstraintsExtension_OID(t *testing.T) {
	ext := &BasicConstraintsExtension{}
	if got := ext.OID(); got != nil {
		t.Errorf("OID() = %v, want nil", got)
	}
}

// Helper functions
func intPtr(i int) *int {
	return &i
}

func intPtrEqual(a, b *int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
