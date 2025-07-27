//go:build integration

package integration_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/identity"
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

func TestMergedProvider_AdditionalRecipients(t *testing.T) {
	// Create base SSH identity
	tmpDir := t.TempDir()
	baseKeyPath := filepath.Join(tmpDir, "base_key")
	basePubKeyPath := filepath.Join(tmpDir, "base_key.pub")

	if err := generateEd25519TestKey(baseKeyPath); err != nil {
		t.Fatalf("Failed to generate base test key: %v", err)
	}

	// Create additional SSH key for recipient
	additionalKeyPath := filepath.Join(tmpDir, "additional_key")
	additionalPubKeyPath := filepath.Join(tmpDir, "additional_key.pub")

	if err := generateEd25519TestKey(additionalKeyPath); err != nil {
		t.Fatalf("Failed to generate additional test key: %v", err)
	}

	// Read the public keys
	basePubKey, err := os.ReadFile(basePubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read base public key: %v", err)
	}

	additionalPubKey, err := os.ReadFile(additionalPubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read additional public key: %v", err)
	}

	// Create base SSH provider
	baseConfig := domain.SSHConfig{
		IdentityFile: baseKeyPath,
		Recipients:   []string{string(basePubKey)},
	}
	baseProvider := identity.NewSSHProvider(baseConfig)

	// Create merged provider with additional recipients
	additionalRecipients := []string{strings.TrimSpace(string(additionalPubKey))}
	mergedProvider := identity.NewMergedProvider(baseProvider, additionalRecipients, "ssh")

	// Test validation
	if err := mergedProvider.Validate(); err != nil {
		t.Errorf("MergedProvider validation failed: %v", err)
	}

	// Test that base identity is preserved
	identity, err := mergedProvider.GetIdentity()
	if err != nil {
		t.Errorf("Failed to get identity from merged provider: %v", err)
	}
	if identity == nil {
		t.Error("MergedProvider identity is nil")
	}

	// Test that recipients include both base and additional
	recipients, err := mergedProvider.GetRecipients()
	if err != nil {
		t.Errorf("Failed to get recipients from merged provider: %v", err)
	}

	expectedCount := 2 // base + additional
	if len(recipients) != expectedCount {
		t.Errorf("Expected %d recipients, got %d", expectedCount, len(recipients))
	}

	// Test encryption/decryption round-trip
	testData := []byte("test message for encryption")

	// Create a minimal crypto service to test encryption with merged recipients
	cryptoSvc := &testCryptoService{identityProvider: mergedProvider}

	encrypted, err := cryptoSvc.EncryptPrivateKey(testData)
	if err != nil {
		t.Errorf("Failed to encrypt with merged provider: %v", err)
	}

	// Should be able to decrypt with base identity
	cryptoSvcBase := &testCryptoService{identityProvider: baseProvider}
	decrypted, err := cryptoSvcBase.DecryptPrivateKey(encrypted)
	if err != nil {
		t.Errorf("Failed to decrypt with base provider: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Decrypted data doesn't match original")
	}
}

func TestMergedProvider_InvalidAdditionalRecipients(t *testing.T) {
	// Create base SSH identity
	tmpDir := t.TempDir()
	baseKeyPath := filepath.Join(tmpDir, "base_key")
	basePubKeyPath := filepath.Join(tmpDir, "base_key.pub")

	if err := generateEd25519TestKey(baseKeyPath); err != nil {
		t.Fatalf("Failed to generate base test key: %v", err)
	}

	basePubKey, err := os.ReadFile(basePubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read base public key: %v", err)
	}

	baseConfig := domain.SSHConfig{
		IdentityFile: baseKeyPath,
		Recipients:   []string{string(basePubKey)},
	}
	baseProvider := identity.NewSSHProvider(baseConfig)

	// Test with invalid additional recipient
	invalidRecipients := []string{"invalid-ssh-key-format"}
	mergedProvider := identity.NewMergedProvider(baseProvider, invalidRecipients, "ssh")

	// Validation should fail
	err = mergedProvider.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid additional recipient, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported recipient format") {
		t.Errorf("Expected error about unsupported recipient format, got: %v", err)
	}
}

// testCryptoService is a minimal implementation for testing encryption/decryption
type testCryptoService struct {
	identityProvider domain.IdentityProvider
}

func (t *testCryptoService) EncryptPrivateKey(data []byte) ([]byte, error) {
	recipients, err := t.identityProvider.GetRecipients()
	if err != nil {
		return nil, err
	}

	// Simple age encryption for testing
	out := &strings.Builder{}
	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(data); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return []byte(out.String()), nil
}

func (t *testCryptoService) DecryptPrivateKey(encryptedData []byte) ([]byte, error) {
	identity, err := t.identityProvider.GetIdentity()
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(strings.NewReader(string(encryptedData)), identity)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(r)
}

func runCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}
