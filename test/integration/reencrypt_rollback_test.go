//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/infra/config"
	cryptosvc "reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/exec"
	"reactor.de/reactor-ca/internal/infra/identity"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/infra/store"
)

// mockStoreWithWriteFailure wraps a real FileStore but fails on specific UpdateEncryptedKey calls
type mockStoreWithWriteFailure struct {
	*store.FileStore
	failOnPath string
	callCount  int
}

func (m *mockStoreWithWriteFailure) UpdateEncryptedKey(path string, data []byte) error {
	m.callCount++
	// Fail on the second write (first write succeeds, second fails to test partial failure)
	if m.callCount == 2 && filepath.Base(path) == filepath.Base(m.failOnPath) {
		return os.ErrPermission // Simulate permission error
	}
	return m.FileStore.UpdateEncryptedKey(path, data)
}

// mockUserInteraction for testing rollback confirmation
type mockUserInteraction struct {
	confirmResponse bool
}

func (m *mockUserInteraction) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, nil
}

func TestReencryptRollback_Integration(t *testing.T) {
	// Set password environment variable
	t.Setenv("REACTOR_CA_PASSWORD", "test-password-123")

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "reactor-ca-rollback-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize PKI structure using the init command
	configDir := filepath.Join(tempDir, "config")
	storeDir := filepath.Join(tempDir, "store")

	// Set up infrastructure components
	logger := &MockLogger{}
	configLoader := config.NewYAMLConfigLoader(configDir)
	realStore := store.NewFileStore(storeDir)
	mockStore := &mockStoreWithWriteFailure{
		FileStore:  realStore,
		failOnPath: filepath.Join(storeDir, "hosts", "db-server", "cert.key.age"),
	}
	passwordProvider := password.NewProvider()
	commander := exec.NewCommander()
	userInteraction := &mockUserInteraction{confirmResponse: true} // Auto-confirm rollback
	identityProviderFactory := identity.NewFactory()
	cryptoServiceFactory := cryptosvc.NewServiceFactory()
	validationService := cryptosvc.NewValidationService()

	// Create application with all required parameters (without crypto services for init)
	appInstance := app.NewApplication(
		tempDir,
		logger,
		configLoader,
		mockStore,
		nil, // cryptoSvc - will be set after init
		passwordProvider,
		userInteraction,
		commander,
		nil, // identityProvider - will be set after init
		identityProviderFactory,
		cryptoServiceFactory,
		validationService,
	)

	// Create directory structure manually
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

	// Override configs with our test values
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

	hostsConfigContent := `
hosts:
  web-server:
    alternative_names:
      dns: ["web.test.com"]
    validity: { days: 90 }
  db-server:
    alternative_names:
      dns: ["db.test.com"]
    validity: { days: 90 }
  api-server:
    alternative_names:
      dns: ["api.test.com"]
    validity: { days: 90 }
`
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yaml"), []byte(hostsConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write hosts.yaml: %v", err)
	}

	// Now load the configs and create crypto services
	cfg, err := configLoader.LoadCA()
	if err != nil {
		t.Fatalf("Failed to load CA config: %v", err)
	}
	identityProvider, err := identityProviderFactory.CreateIdentityProvider(cfg, passwordProvider)
	if err != nil {
		t.Fatalf("Failed to create identity provider: %v", err)
	}
	cryptoSvc := cryptoServiceFactory.CreateCryptoService(identityProvider)

	// Update the application with crypto services (recreate instance)
	appInstance = app.NewApplication(
		tempDir,
		logger,
		configLoader,
		mockStore,
		cryptoSvc,
		passwordProvider,
		userInteraction,
		commander,
		identityProvider,
		identityProviderFactory,
		cryptoServiceFactory,
		validationService,
	)

	ctx := context.Background()

	// 1. Create initial PKI setup with real .age files
	t.Log("Creating CA...")
	if err := appInstance.CreateCA(ctx, false); err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	t.Log("Creating host certificates...")
	if err := appInstance.IssueHost(ctx, "web-server", false, false); err != nil {
		t.Fatalf("Failed to issue web-server cert: %v", err)
	}
	if err := appInstance.IssueHost(ctx, "db-server", false, false); err != nil {
		t.Fatalf("Failed to issue db-server cert: %v", err)
	}
	if err := appInstance.IssueHost(ctx, "api-server", false, false); err != nil {
		t.Fatalf("Failed to issue api-server cert: %v", err)
	}

	// 2. Verify initial setup
	expectedFiles := []string{
		"store/ca/ca.crt",
		"store/ca/ca.key.age",
		"store/hosts/web-server/cert.crt",
		"store/hosts/web-server/cert.key.age",
		"store/hosts/db-server/cert.crt",
		"store/hosts/db-server/cert.key.age",
		"store/hosts/api-server/cert.crt",
		"store/hosts/api-server/cert.key.age",
	}

	for _, file := range expectedFiles {
		fullPath := filepath.Join(tempDir, file)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Fatalf("Expected file not found: %s", file)
		}
	}

	// 3. Capture original file content for verification
	originalCAKey, err := os.ReadFile(filepath.Join(tempDir, "store/ca/ca.key.age"))
	if err != nil {
		t.Fatalf("Failed to read original CA key: %v", err)
	}
	originalWebKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/web-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read original web-server key: %v", err)
	}
	originalDBKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/db-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read original db-server key: %v", err)
	}
	originalAPIKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/api-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read original api-server key: %v", err)
	}

	// 4. Attempt reencrypt with rollback flag - should fail on second write, then rollback
	t.Log("Attempting reencrypt with controlled failure...")
	err = appInstance.ReencryptKeys(ctx, false, true) // force=false, rollback=true
	if err == nil {
		t.Fatal("Expected reencrypt to fail due to mock write failure, but it succeeded")
	}

	t.Logf("Reencrypt failed as expected: %v", err)

	// 5. Verify .bak files were created during backup phase
	expectedBackupFiles := []string{
		"store/ca/ca.key.age.bak",
		"store/hosts/web-server/cert.key.age.bak",
		"store/hosts/db-server/cert.key.age.bak",
		"store/hosts/api-server/cert.key.age.bak",
	}

	// Note: .bak files should be cleaned up after rollback, so we verify they DON'T exist
	for _, bakFile := range expectedBackupFiles {
		fullPath := filepath.Join(tempDir, bakFile)
		if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
			t.Errorf("Backup file should have been cleaned up after rollback: %s", bakFile)
		}
	}

	// 6. Verify original files were restored unchanged by rollback
	currentCAKey, err := os.ReadFile(filepath.Join(tempDir, "store/ca/ca.key.age"))
	if err != nil {
		t.Fatalf("Failed to read current CA key: %v", err)
	}
	if string(originalCAKey) != string(currentCAKey) {
		t.Error("CA key was not properly restored by rollback")
	}

	currentWebKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/web-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read current web-server key: %v", err)
	}
	if string(originalWebKey) != string(currentWebKey) {
		t.Error("Web-server key was not properly restored by rollback")
	}

	currentDBKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/db-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read current db-server key: %v", err)
	}
	if string(originalDBKey) != string(currentDBKey) {
		t.Error("DB-server key was not properly restored by rollback")
	}

	currentAPIKey, err := os.ReadFile(filepath.Join(tempDir, "store/hosts/api-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read current api-server key: %v", err)
	}
	if string(originalAPIKey) != string(currentAPIKey) {
		t.Error("API-server key was not properly restored by rollback")
	}

	// 7. Verify normal reencrypt works after removing the mock failure
	t.Log("Testing normal reencrypt after fixing mock...")
	mockStore.failOnPath = "" // Disable failure injection
	mockStore.callCount = 0   // Reset counter

	if err := appInstance.ReencryptKeys(ctx, false, false); err != nil {
		t.Fatalf("Normal reencrypt should succeed after removing mock failure: %v", err)
	}

	// 8. Verify .bak files are cleaned up after successful reencrypt
	for _, bakFile := range expectedBackupFiles {
		fullPath := filepath.Join(tempDir, bakFile)
		if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
			t.Errorf("Backup file should have been cleaned up after successful reencrypt: %s", bakFile)
		}
	}

	t.Log("Integration test completed successfully")
}
