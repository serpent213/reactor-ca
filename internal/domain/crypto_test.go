//go:build !integration && !e2e

package domain

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func TestHashAlgorithm_ToCryptoHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     HashAlgorithm
		expected crypto.Hash
		wantErr  bool
	}{
		{
			name:     "SHA256",
			hash:     SHA256,
			expected: crypto.SHA256,
			wantErr:  false,
		},
		{
			name:     "SHA384",
			hash:     SHA384,
			expected: crypto.SHA384,
			wantErr:  false,
		},
		{
			name:     "SHA512",
			hash:     SHA512,
			expected: crypto.SHA512,
			wantErr:  false,
		},
		{
			name:    "invalid algorithm",
			hash:    HashAlgorithm("INVALID"),
			wantErr: true,
		},
		{
			name:    "empty algorithm",
			hash:    HashAlgorithm(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.hash.ToCryptoHash()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ToCryptoHash() expected error, got nil")
					return
				}
				if err != x509.ErrUnsupportedAlgorithm {
					t.Errorf("ToCryptoHash() expected ErrUnsupportedAlgorithm, got %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("ToCryptoHash() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("ToCryptoHash() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
