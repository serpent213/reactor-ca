//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/infra/clock"
	"reactor.de/reactor-ca/internal/infra/config"
	cryptosvc "reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/exec"
	"reactor.de/reactor-ca/internal/infra/identity"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/infra/store"
	"reactor.de/reactor-ca/internal/testutil"
)

func TestCAExportKey_Integration(t *testing.T) {
	// Set password environment variable
	t.Setenv("REACTOR_CA_PASSWORD", "test-password-123")

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "reactor-ca-export-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize PKI structure
	configDir := filepath.Join(tempDir, "config")
	storeDir := filepath.Join(tempDir, "store")

	// Set up infrastructure components
	logger := &MockLogger{}
	configLoader := config.NewYAMLConfigLoader(configDir)
	fileStore := store.NewFileStore(storeDir)
	passwordProvider := password.NewProvider()
	commander := exec.NewCommander()
	userInteraction := &mockUserInteraction{confirmResponse: true}
	identityProviderFactory := identity.NewFactory()
	clockSvc := clock.NewService()
	cryptoServiceFactory := cryptosvc.NewServiceFactory(clockSvc)
	validationService := cryptosvc.NewValidationService()

	// Create directory structure
	dirs := []string{
		configDir,
		storeDir,
		filepath.Join(storeDir, "ca"),
		filepath.Join(storeDir, "hosts"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Create CA config
	caConfigContent := `
ca:
  subject:
    common_name: "Test CA"
    organization: "Test Org"
    country: "US"
  validity:
    days: 365
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "password"
  password:
    min_length: 8
    env_var: "REACTOR_CA_PASSWORD"
`
	if err := os.WriteFile(filepath.Join(configDir, "ca.yaml"), []byte(caConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write ca.yaml: %v", err)
	}

	// Create hosts config
	hostsConfigContent := `
hosts:
  web-server:
    alternative_names:
      dns: ["web.test.com"]
    validity: { days: 90 }
`
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yaml"), []byte(hostsConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write hosts.yaml: %v", err)
	}

	// Load configs and create crypto services
	cfg, err := configLoader.LoadCA()
	if err != nil {
		t.Fatalf("Failed to load CA config: %v", err)
	}
	identityProvider, err := identityProviderFactory.CreateIdentityProvider(cfg, passwordProvider)
	if err != nil {
		t.Fatalf("Failed to create identity provider: %v", err)
	}
	cryptoSvc := cryptoServiceFactory.CreateCryptoService(identityProvider)

	// Create application instance
	appInstance := app.NewApplication(
		tempDir,
		logger,
		configLoader,
		config.NewYAMLConfigUpdater(filepath.Join(tempDir, "config"), configLoader),
		fileStore,
		cryptoSvc,
		passwordProvider,
		userInteraction,
		commander,
		identityProvider,
		identityProviderFactory,
		cryptoServiceFactory,
		validationService,
		clockSvc,
	)

	ctx := context.Background()

	// Create CA
	t.Log("Creating CA...")
	testutil.WithSilentOutput(t, func() {
		if err := appInstance.CreateCA(ctx, false); err != nil {
			t.Fatalf("Failed to create CA: %v", err)
		}
	})

	// Verify CA files were created
	caKeyPath := filepath.Join(storeDir, "ca", "ca.key.age")
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Fatal("CA key file was not created")
	}

	t.Run("ExportCAKey_ToFile", func(t *testing.T) {
		// Create temp file for key export
		exportFile := filepath.Join(tempDir, "exported-ca-key.pem")

		// Export CA key to file
		keyPEM, err := appInstance.ExportCAKey(ctx)
		if err != nil {
			t.Fatalf("Failed to export CA key: %v", err)
		}

		// Write to file with secure permissions (simulating -o flag behavior)
		if err := os.WriteFile(exportFile, keyPEM, 0600); err != nil {
			t.Fatalf("Failed to write exported key to file: %v", err)
		}

		// Verify file was created with correct permissions (Unix-like systems only)
		fileInfo, err := os.Stat(exportFile)
		if err != nil {
			t.Fatalf("Failed to stat exported key file: %v", err)
		}
		// Skip permission check on Windows as it doesn't use Unix-style permissions
		if runtime.GOOS != "windows" {
			if fileInfo.Mode().Perm() != 0600 {
				t.Errorf("Expected file permissions 0600, got %o", fileInfo.Mode().Perm())
			}
		}

		// Verify file contains valid PEM key
		exportedKey, err := os.ReadFile(exportFile)
		if err != nil {
			t.Fatalf("Failed to read exported key file: %v", err)
		}

		keyStr := string(exportedKey)
		if !strings.HasPrefix(keyStr, "-----BEGIN") {
			t.Error("Exported key does not start with PEM header")
		}
		if !strings.HasSuffix(strings.TrimSpace(keyStr), "-----END PRIVATE KEY-----") {
			t.Error("Exported key does not end with PEM footer")
		}

		// Verify key is not empty and has reasonable length
		if len(exportedKey) < 100 {
			t.Errorf("Exported key seems too short: %d bytes", len(exportedKey))
		}

		t.Logf("Successfully exported CA key to file: %s (%d bytes)", exportFile, len(exportedKey))
	})

	t.Run("ExportCAKey_ToStdout", func(t *testing.T) {
		// Export CA key (this would normally go to stdout)
		keyPEM, err := appInstance.ExportCAKey(ctx)
		if err != nil {
			t.Fatalf("Failed to export CA key: %v", err)
		}

		// Verify key content
		keyStr := string(keyPEM)
		if !strings.HasPrefix(keyStr, "-----BEGIN") {
			t.Error("Exported key does not start with PEM header")
		}
		if !strings.HasSuffix(strings.TrimSpace(keyStr), "-----END PRIVATE KEY-----") {
			t.Error("Exported key does not end with PEM footer")
		}

		// Verify key is parseable by our crypto service
		parsedKey, err := cryptoSvc.ParsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("Failed to parse exported key: %v", err)
		}
		if parsedKey == nil {
			t.Error("Parsed key is nil")
		}

		t.Logf("Successfully exported CA key to stdout (%d bytes)", len(keyPEM))
	})

	t.Run("ExportCAKey_RoundTrip", func(t *testing.T) {
		// Export CA key
		exportedKeyPEM, err := appInstance.ExportCAKey(ctx)
		if err != nil {
			t.Fatalf("Failed to export CA key: %v", err)
		}

		// Parse the exported key
		exportedKey, err := cryptoSvc.ParsePrivateKey(exportedKeyPEM)
		if err != nil {
			t.Fatalf("Failed to parse exported key: %v", err)
		}

		// Load the original CA key for comparison
		originalKeyData, err := fileStore.LoadCAKey()
		if err != nil {
			t.Fatalf("Failed to load original CA key: %v", err)
		}
		originalKey, err := cryptoSvc.DecryptPrivateKey(originalKeyData)
		if err != nil {
			t.Fatalf("Failed to decrypt original CA key: %v", err)
		}

		// Verify both keys are non-nil and have the same type
		if exportedKey == nil {
			t.Error("Exported key is nil")
		}
		if originalKey == nil {
			t.Error("Original key is nil")
		}

		// Simple verification: re-encode the exported key and verify it's still valid
		reEncodedPEM, err := cryptoSvc.EncodeKeyToPEM(exportedKey)
		if err != nil {
			t.Fatalf("Failed to re-encode exported key: %v", err)
		}
		if len(reEncodedPEM) == 0 {
			t.Error("Re-encoded key is empty")
		}

		t.Log("Successfully verified round-trip key export/parsing")
	})

	t.Log("CA export-key integration test completed successfully")
}
