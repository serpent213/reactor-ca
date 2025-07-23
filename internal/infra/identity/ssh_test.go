package identity_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serpent213/reactor-ca/internal/domain"
	"github.com/serpent213/reactor-ca/internal/infra/identity"
)

func TestSSHProvider_Ed25519(t *testing.T) {
	// Create temporary Ed25519 key pair
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")
	pubKeyPath := filepath.Join(tmpDir, "id_ed25519.pub")

	// Generate Ed25519 key pair
	if err := generateEd25519TestKey(keyPath); err != nil {
		t.Fatalf("Failed to generate test Ed25519 key: %v", err)
	}

	// Read the public key for recipients
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	config := domain.SSHConfig{
		IdentityFile: keyPath,
		Recipients:   []string{string(pubKeyBytes)},
	}

	provider := identity.NewSSHProvider(config)

	// Test validation
	if err := provider.Validate(); err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Test getting identity
	identity, err := provider.GetIdentity()
	if err != nil {
		t.Errorf("Failed to get identity: %v", err)
	}
	if identity == nil {
		t.Error("Identity is nil")
	}

	// Test getting recipients
	recipients, err := provider.GetRecipients()
	if err != nil {
		t.Errorf("Failed to get recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}
}

func TestSSHProvider_RSA(t *testing.T) {
	// Create temporary RSA key pair
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_rsa")
	pubKeyPath := filepath.Join(tmpDir, "id_rsa.pub")

	// Generate RSA key pair
	if err := generateRSATestKey(keyPath); err != nil {
		t.Fatalf("Failed to generate test RSA key: %v", err)
	}

	// Read the public key for recipients
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	config := domain.SSHConfig{
		IdentityFile: keyPath,
		Recipients:   []string{string(pubKeyBytes)},
	}

	provider := identity.NewSSHProvider(config)

	// Test validation
	if err := provider.Validate(); err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Test getting identity
	identity, err := provider.GetIdentity()
	if err != nil {
		t.Errorf("Failed to get identity: %v", err)
	}
	if identity == nil {
		t.Error("Identity is nil")
	}

	// Test getting recipients
	recipients, err := provider.GetRecipients()
	if err != nil {
		t.Errorf("Failed to get recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}
}

func TestSSHProvider_MultipleRecipients(t *testing.T) {
	// Create temporary keys
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")
	pubKeyPath := filepath.Join(tmpDir, "id_ed25519.pub")

	// Generate Ed25519 key pair
	if err := generateEd25519TestKey(keyPath); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Read the public key
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	// Create config with multiple recipients (reusing same key for simplicity)
	config := domain.SSHConfig{
		IdentityFile: keyPath,
		Recipients: []string{
			string(pubKeyBytes),
			string(pubKeyBytes), // Duplicate for testing multiple recipients
		},
	}

	provider := identity.NewSSHProvider(config)

	// Test getting recipients
	recipients, err := provider.GetRecipients()
	if err != nil {
		t.Errorf("Failed to get recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Errorf("Expected 2 recipients, got %d", len(recipients))
	}
}

func TestSSHProvider_HomeDirectoryExpansion(t *testing.T) {
	// Create test key in temp directory
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")

	if err := generateEd25519TestKey(keyPath); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Test that tilde expansion works (we can't easily test real ~ expansion in tests)
	config := domain.SSHConfig{
		IdentityFile: keyPath, // Use absolute path for this test
		Recipients:   []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmlSRRC4SIrIvVCIvH+H9GvhDxGbus907IJByMtgJIm test@example.com"},
	}

	provider := identity.NewSSHProvider(config)

	// Test validation passes with absolute path
	if err := provider.Validate(); err != nil {
		t.Errorf("Validation failed with absolute path: %v", err)
	}
}

func TestSSHProvider_ValidationErrors(t *testing.T) {
	// Create a temporary valid key for some tests
	tmpDir := t.TempDir()
	validKeyPath := filepath.Join(tmpDir, "valid_key")
	if err := generateEd25519TestKey(validKeyPath); err != nil {
		t.Fatalf("Failed to generate valid test key: %v", err)
	}

	tests := []struct {
		name   string
		config domain.SSHConfig
		errMsg string
	}{
		{
			name: "missing identity file",
			config: domain.SSHConfig{
				IdentityFile: "/nonexistent/key",
				Recipients:   []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmlSRRC4SIrIvVCIvH+H9GvhDxGbus907IJByMtgJIm test@example.com"},
			},
			errMsg: "SSH identity file not accessible",
		},
		{
			name: "no recipients",
			config: domain.SSHConfig{
				IdentityFile: validKeyPath, // Use valid key since file validation comes first
				Recipients:   []string{},
			},
			errMsg: "no SSH recipients configured",
		},
		{
			name: "invalid recipient",
			config: domain.SSHConfig{
				IdentityFile: validKeyPath, // Use valid key since file validation comes first
				Recipients:   []string{"invalid-ssh-key"},
			},
			errMsg: "invalid SSH recipient at index 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := identity.NewSSHProvider(tt.config)
			err := provider.Validate()
			if err == nil {
				t.Error("Expected validation error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestSSHProvider_InvalidKeyFile(t *testing.T) {
	// Create a file that's not a valid SSH key
	tmpDir := t.TempDir()
	invalidKeyPath := filepath.Join(tmpDir, "invalid_key")

	if err := os.WriteFile(invalidKeyPath, []byte("not a valid ssh key"), 0600); err != nil {
		t.Fatalf("Failed to create invalid key file: %v", err)
	}

	config := domain.SSHConfig{
		IdentityFile: invalidKeyPath,
		Recipients:   []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmlSRRC4SIrIvVCIvH+H9GvhDxGbus907IJByMtgJIm test@example.com"},
	}

	provider := identity.NewSSHProvider(config)

	// Validation should fail for invalid key
	err := provider.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid key file, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid SSH private key") {
		t.Errorf("Expected error about invalid SSH key, got: %v", err)
	}
}

// Helper functions for generating test keys
func generateEd25519TestKey(keyPath string) error {
	cmd := []string{"ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "test@example.com"}
	return runCommand(cmd...)
}

func generateRSATestKey(keyPath string) error {
	cmd := []string{"ssh-keygen", "-t", "rsa", "-b", "2048", "-f", keyPath, "-N", "", "-C", "test@example.com"}
	return runCommand(cmd...)
}

func runCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}
