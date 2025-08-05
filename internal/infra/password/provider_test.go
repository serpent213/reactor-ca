//go:build !integration && !e2e

package password

import (
	"context"
	"testing"

	"reactor.de/reactor-ca/internal/domain"
)

func TestStaticPasswordProvider_GetNewMasterPassword(t *testing.T) {
	tests := []struct {
		name      string
		password  []byte
		minLength int
		wantErr   bool
	}{
		{
			name:      "valid password",
			password:  []byte("test-password-123"),
			minLength: 8,
			wantErr:   false,
		},
		{
			name:      "empty password",
			password:  []byte(""),
			minLength: 8,
			wantErr:   false, // StaticPasswordProvider doesn't validate length
		},
		{
			name:      "nil password",
			password:  nil,
			minLength: 8,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &StaticPasswordProvider{
				Password: tt.password,
			}

			result, err := provider.GetNewMasterPassword(context.Background(), domain.PasswordConfig{}, tt.minLength)

			if tt.wantErr {
				if err == nil {
					t.Error("GetNewMasterPassword() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GetNewMasterPassword() unexpected error: %v", err)
				return
			}

			// Verify password is returned as-is
			if string(result) != string(tt.password) {
				t.Errorf("GetNewMasterPassword() = %q, expected %q", string(result), string(tt.password))
			}
		})
	}
}
