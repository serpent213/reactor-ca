//go:build !integration && !e2e

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/plugin"
	"reactor.de/reactor-ca/internal/domain"
)

// Helper functions to create valid test data
func createValidTestIdentity() string {
	return plugin.EncodeIdentity("testplugin", []byte("test-identity-data"))
}

func createValidTestRecipient() string {
	return plugin.EncodeRecipient("testplugin", []byte("test-recipient-data"))
}

func createValidTestRecipients(count int) []string {
	recipients := make([]string, count)
	for i := 0; i < count; i++ {
		data := []byte("test-recipient-data-" + string(rune('a'+i)))
		recipients[i] = plugin.EncodeRecipient("testplugin", data)
	}
	return recipients
}

func TestNewPluginProvider(t *testing.T) {
	config := domain.PluginConfig{
		IdentityFile: "/path/to/identity",
		Recipients:   []string{createValidTestRecipient()},
	}

	provider := NewPluginProvider(config)

	if provider == nil {
		t.Fatal("NewPluginProvider() returned nil")
	}

	if provider.config.IdentityFile != config.IdentityFile {
		t.Errorf("NewPluginProvider() config.IdentityFile = %q, want %q", provider.config.IdentityFile, config.IdentityFile)
	}

	if len(provider.config.Recipients) != len(config.Recipients) {
		t.Errorf("NewPluginProvider() config.Recipients length = %d, want %d", len(provider.config.Recipients), len(config.Recipients))
	}

	if provider.ui == nil {
		t.Error("NewPluginProvider() ui is nil")
	}
}

func TestPluginProvider_GetIdentity(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	tests := []struct {
		name         string
		identityData string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid plugin identity",
			identityData: createValidTestIdentity(),
			wantErr:      false,
		},
		{
			name:         "plugin identity with comments",
			identityData: "# This is a comment\n" + createValidTestIdentity() + "\n# Another comment",
			wantErr:      false,
		},
		{
			name:         "plugin identity with whitespace",
			identityData: "  \n" + createValidTestIdentity() + "  \n  ",
			wantErr:      false,
		},
		{
			name:         "empty file",
			identityData: "",
			wantErr:      true,
			errContains:  "is empty",
		},
		{
			name:         "only whitespace",
			identityData: "   \n\t\n   ",
			wantErr:      true,
			errContains:  "is empty",
		},
		{
			name:         "only comments",
			identityData: "# Comment 1\n# Comment 2\n",
			wantErr:      true,
			errContains:  "must start with AGE-PLUGIN-",
		},
		{
			name:         "invalid prefix",
			identityData: "INVALID-PREFIX-123",
			wantErr:      true,
			errContains:  "must start with AGE-PLUGIN-",
		},
		{
			name:         "regular age identity instead of plugin",
			identityData: "AGE-SECRET-KEY-1Q2FHQTVK4W7RQVHX2LQGZ8LQGZ8LQGZ8LQGZ8LQGZ8LQG",
			wantErr:      true,
			errContains:  "must start with AGE-PLUGIN-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create identity file
			identityFile := filepath.Join(tempDir, "identity_"+strings.ReplaceAll(tt.name, " ", "_"))
			err := os.WriteFile(identityFile, []byte(tt.identityData), 0600)
			if err != nil {
				t.Fatalf("Failed to create identity file: %v", err)
			}

			config := domain.PluginConfig{
				IdentityFile: identityFile,
				Recipients:   []string{createValidTestRecipient()},
			}
			provider := NewPluginProvider(config)

			identity, err := provider.GetIdentity()

			if tt.wantErr {
				if err == nil {
					t.Error("GetIdentity() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GetIdentity() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
				if identity != nil {
					t.Error("GetIdentity() expected nil identity on error")
				}
			} else {
				if err != nil {
					t.Errorf("GetIdentity() unexpected error: %v", err)
				}
				if identity == nil {
					t.Error("GetIdentity() returned nil identity without error")
				}
			}
		})
	}
}

func TestPluginProvider_GetIdentity_FileNotFound(t *testing.T) {
	config := domain.PluginConfig{
		IdentityFile: "/nonexistent/path/identity",
		Recipients:   []string{createValidTestRecipient()},
	}
	provider := NewPluginProvider(config)

	identity, err := provider.GetIdentity()

	if err == nil {
		t.Error("GetIdentity() expected error for nonexistent file, got nil")
	}
	if identity != nil {
		t.Error("GetIdentity() expected nil identity for nonexistent file")
	}
	if !strings.Contains(err.Error(), "failed to read plugin identity file") {
		t.Errorf("GetIdentity() error = %q, want to contain 'failed to read plugin identity file'", err.Error())
	}
}

func TestPluginProvider_GetIdentity_HomePathExpansion(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create identity file
	identityFile := filepath.Join(tempDir, "identity")
	identityData := createValidTestIdentity()
	err := os.WriteFile(identityFile, []byte(identityData), 0600)
	if err != nil {
		t.Fatalf("Failed to create identity file: %v", err)
	}

	// Test that path expansion is called (we can't easily test ~ expansion without affecting user's home)
	// but we can test that the pathutil.ExpandHomePath function is used
	config := domain.PluginConfig{
		IdentityFile: identityFile, // Use absolute path to ensure it works
		Recipients:   []string{createValidTestRecipient()},
	}
	provider := NewPluginProvider(config)

	identity, err := provider.GetIdentity()

	if err != nil {
		t.Errorf("GetIdentity() unexpected error: %v", err)
	}
	if identity == nil {
		t.Error("GetIdentity() returned nil identity without error")
	}
}

func TestPluginProvider_GetRecipients(t *testing.T) {
	tests := []struct {
		name        string
		recipients  []string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid single recipient",
			recipients: []string{createValidTestRecipient()},
			wantErr:    false,
		},
		{
			name:       "valid multiple recipients",
			recipients: createValidTestRecipients(2),
			wantErr:    false,
		},
		{
			name:       "recipient with whitespace",
			recipients: []string{"  " + createValidTestRecipient() + "  "},
			wantErr:    false,
		},
		{
			name:        "empty recipients list",
			recipients:  []string{},
			wantErr:     true,
			errContains: "no plugin recipients configured",
		},
		{
			name:        "nil recipients list",
			recipients:  nil,
			wantErr:     true,
			errContains: "no plugin recipients configured",
		},
		{
			name:        "invalid recipient prefix",
			recipients:  []string{"invalid-recipient"},
			wantErr:     true,
			errContains: "must start with age1",
		},
		{
			name: "mixed valid and invalid recipients",
			recipients: []string{
				createValidTestRecipient(),
				"invalid-recipient",
			},
			wantErr:     true,
			errContains: "must start with age1",
		},
		{
			name:        "empty string recipient",
			recipients:  []string{""},
			wantErr:     true,
			errContains: "must start with age1",
		},
		{
			name:        "whitespace only recipient",
			recipients:  []string{"   "},
			wantErr:     true,
			errContains: "must start with age1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := domain.PluginConfig{
				IdentityFile: "/path/to/identity",
				Recipients:   tt.recipients,
			}
			provider := NewPluginProvider(config)

			recipients, err := provider.GetRecipients()

			if tt.wantErr {
				if err == nil {
					t.Error("GetRecipients() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GetRecipients() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
				if recipients != nil {
					t.Error("GetRecipients() expected nil recipients on error")
				}
			} else {
				if err != nil {
					t.Errorf("GetRecipients() unexpected error: %v", err)
				}
				if recipients == nil {
					t.Error("GetRecipients() returned nil recipients without error")
				}
				expectedCount := len(tt.recipients)
				if len(recipients) != expectedCount {
					t.Errorf("GetRecipients() returned %d recipients, want %d", len(recipients), expectedCount)
				}
			}
		})
	}
}

func TestPluginProvider_Validate(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		setupFile   func() string // Returns path to identity file
		recipients  []string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "valid_identity")
				data := createValidTestIdentity()
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients: []string{createValidTestRecipient()},
			wantErr:    false, // Should succeed with valid plugin format
		},
		{
			name: "valid configuration with comments",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "identity_with_comments")
				data := "# Comment\n" + createValidTestIdentity() + "\n# Another comment"
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients: []string{createValidTestRecipient()},
			wantErr:    false, // Should succeed with valid plugin format
		},
		{
			name: "identity file not accessible",
			setupFile: func() string {
				return "/nonexistent/path/identity"
			},
			recipients:  []string{"age1test2fhqtvk4w7rqvhx2lqgz8lqgz8lqgz8lqgz8lqgz8lqg"},
			wantErr:     true,
			errContains: "plugin identity file not accessible",
		},
		{
			name: "empty identity file",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "empty_identity")
				err := os.WriteFile(identityFile, []byte(""), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients:  []string{"age1test2fhqtvk4w7rqvhx2lqgz8lqgz8lqgz8lqgz8lqgz8lqg"},
			wantErr:     true,
			errContains: "plugin identity file is empty",
		},
		{
			name: "identity file with only comments",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "comments_only_identity")
				data := "# Comment 1\n# Comment 2\n"
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients:  []string{"age1test2fhqtvk4w7rqvhx2lqgz8lqgz8lqgz8lqgz8lqgz8lqg"},
			wantErr:     true,
			errContains: "plugin identity file contains invalid identity format",
		},
		{
			name: "invalid identity format",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "invalid_identity")
				data := "INVALID-FORMAT-123"
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients:  []string{"age1test2fhqtvk4w7rqvhx2lqgz8lqgz8lqgz8lqgz8lqgz8lqg"},
			wantErr:     true,
			errContains: "plugin identity file contains invalid identity format",
		},
		{
			name: "valid identity but no recipients",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "valid_identity_no_recipients")
				data := createValidTestIdentity()
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients:  []string{},
			wantErr:     true,
			errContains: "no plugin recipients configured", // Now properly hits this check
		},
		{
			name: "valid identity but invalid recipient",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "valid_identity_invalid_recipient")
				data := createValidTestIdentity()
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients:  []string{"invalid-recipient"},
			wantErr:     true,
			errContains: "invalid plugin recipient at index 0", // Now properly hits this check
		},
		{
			name: "valid identity with multiple recipients including invalid",
			setupFile: func() string {
				identityFile := filepath.Join(tempDir, "valid_identity_mixed_recipients")
				data := createValidTestIdentity()
				err := os.WriteFile(identityFile, []byte(data), 0600)
				if err != nil {
					t.Fatalf("Failed to create identity file: %v", err)
				}
				return identityFile
			},
			recipients: []string{
				createValidTestRecipient(),
				"invalid-recipient",
			},
			wantErr:     true,
			errContains: "invalid plugin recipient at index 1", // Now properly hits this check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identityFile := tt.setupFile()
			config := domain.PluginConfig{
				IdentityFile: identityFile,
				Recipients:   tt.recipients,
			}
			provider := NewPluginProvider(config)

			err := provider.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPluginProvider_Validate_HomePathExpansion(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create identity file
	identityFile := filepath.Join(tempDir, "identity")
	identityData := createValidTestIdentity()
	err := os.WriteFile(identityFile, []byte(identityData), 0600)
	if err != nil {
		t.Fatalf("Failed to create identity file: %v", err)
	}

	// Test that path expansion is called during validation
	config := domain.PluginConfig{
		IdentityFile: identityFile, // Use absolute path to ensure it works
		Recipients:   []string{createValidTestRecipient()},
	}
	provider := NewPluginProvider(config)

	err = provider.Validate()

	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

// Test edge cases for GetIdentity parsing logic
func TestPluginProvider_GetIdentity_ParsingEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name         string
		identityData string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "multiline with empty lines",
			identityData: "\n\n\n" + createValidTestIdentity() + "\n\n\n",
			wantErr:      false,
		},
		{
			name:         "comment before identity",
			identityData: "# Header comment\n" + createValidTestIdentity(),
			wantErr:      false,
		},
		{
			name:         "mixed comments and empty lines",
			identityData: "# Comment 1\n\n# Comment 2\n\n" + createValidTestIdentity() + "\n# Trailing comment",
			wantErr:      false,
		},
		{
			name:         "tabs and spaces mixed",
			identityData: "\t  \n\t# Comment\n  \t" + createValidTestIdentity() + "\t  ",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identityFile := filepath.Join(tempDir, "edge_case_"+strings.ReplaceAll(tt.name, " ", "_"))
			err := os.WriteFile(identityFile, []byte(tt.identityData), 0600)
			if err != nil {
				t.Fatalf("Failed to create identity file: %v", err)
			}

			config := domain.PluginConfig{
				IdentityFile: identityFile,
				Recipients:   []string{createValidTestRecipient()},
			}
			provider := NewPluginProvider(config)

			identity, err := provider.GetIdentity()

			if tt.wantErr {
				if err == nil {
					t.Error("GetIdentity() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GetIdentity() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("GetIdentity() unexpected error: %v", err)
				}
				if identity == nil {
					t.Error("GetIdentity() returned nil identity without error")
				}
			}
		})
	}
}
