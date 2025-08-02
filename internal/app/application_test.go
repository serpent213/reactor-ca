//go:build !integration && !e2e

package app_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/testutil"
)

// --- Domain Mocks ---

type mockUserInteraction struct {
	confirmResponse bool
	confirmErr      error
}

func (m *mockUserInteraction) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, m.confirmErr
}

// --- Infrastructure Mocks ---

type mockStore struct {
	hostIDs           []string
	deletedIDs        []string
	encryptedKeyPaths []string
	keyData           map[string][]byte
	updateKeyError    error
	err               error
	caCert            *x509.Certificate
}

func (m *mockStore) ListHostIDs() ([]string, error) {
	return m.hostIDs, m.err
}

func (m *mockStore) DeleteHost(hostID string) error {
	if m.err != nil {
		return m.err
	}
	m.deletedIDs = append(m.deletedIDs, hostID)
	return nil
}

func (m *mockStore) GetAllEncryptedKeyPaths() ([]string, error) {
	return m.encryptedKeyPaths, m.err
}

func (m *mockStore) UpdateEncryptedKey(path string, data []byte) error {
	if m.updateKeyError != nil {
		return m.updateKeyError
	}
	if m.keyData == nil {
		m.keyData = make(map[string][]byte)
	}
	m.keyData[path] = data
	return nil
}

// Minimal Store interface implementations
func (m *mockStore) CAExists() (bool, error)                               { return false, nil }
func (m *mockStore) SaveCA(cert, encryptedKey []byte) error                { return nil }
func (m *mockStore) LoadCACert() (*x509.Certificate, error)                { return m.caCert, m.err }
func (m *mockStore) LoadCAKey() ([]byte, error)                            { return nil, nil }
func (m *mockStore) HostExists(hostID string) (bool, error)                { return false, nil }
func (m *mockStore) HostKeyExists(hostID string) (bool, error)             { return false, nil }
func (m *mockStore) HostCertExists(hostID string) (bool, error)            { return false, nil }
func (m *mockStore) SaveHostCert(hostID string, cert []byte) error         { return nil }
func (m *mockStore) SaveHostKey(hostID string, encryptedKey []byte) error  { return nil }
func (m *mockStore) LoadHostCert(hostID string) (*x509.Certificate, error) { return nil, nil }
func (m *mockStore) LoadHostKey(hostID string) ([]byte, error)             { return nil, nil }
func (m *mockStore) GetHostCertPath(hostID string) string                  { return "" }
func (m *mockStore) GetHostKeyPath(hostID string) string                   { return "" }
func (m *mockStore) GetCACertPath() string                                 { return "" }

// Backup operations - mock implementations
func (m *mockStore) CreateBackupFile(originalPath string) error  { return nil }
func (m *mockStore) RestoreFromBackup(originalPath string) error { return nil }
func (m *mockStore) RemoveBackupFile(originalPath string) error  { return nil }

// --- Tests ---

func TestCleanHosts(t *testing.T) {
	errInput := errors.New("input error")

	testCases := []struct {
		name              string
		storeIDs          []string
		configIDs         []string
		force             bool
		confirmResponse   bool
		confirmError      error
		expectedPruned    []string
		expectedErr       error
		expectStoreDelete bool
	}{
		{
			name:           "No hosts to prune",
			storeIDs:       []string{"host1", "host2"},
			configIDs:      []string{"host1", "host2"},
			force:          true,
			expectedPruned: nil,
			expectedErr:    nil,
		},
		{
			name:              "Prune one host with force",
			storeIDs:          []string{"host1", "host2-to-prune"},
			configIDs:         []string{"host1"},
			force:             true,
			expectedPruned:    []string{"host2-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:              "Prune multiple hosts with confirmation",
			storeIDs:          []string{"host1", "host2-to-prune", "host3-to-prune"},
			configIDs:         []string{"host1"},
			force:             false,
			confirmResponse:   true,
			expectedPruned:    []string{"host2-to-prune", "host3-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:            "Prune aborted by user",
			storeIDs:        []string{"host1", "host2-to-prune"},
			configIDs:       []string{"host1"},
			force:           false,
			confirmResponse: false,
			expectedPruned:  nil,
			expectedErr:     domain.ErrActionAborted,
		},
		{
			name:           "Confirmation fails",
			storeIDs:       []string{"host1", "host2-to-prune"},
			configIDs:      []string{"host1"},
			force:          false,
			confirmError:   errInput,
			expectedPruned: nil,
			expectedErr:    errInput,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Mocks
			mockCfgLoader := &MockConfigLoader{
				HostsConfig: &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)},
			}
			for _, id := range tc.configIDs {
				mockCfgLoader.HostsConfig.Hosts[id] = domain.HostConfig{}
			}

			mockStore := &mockStore{
				hostIDs: tc.storeIDs,
			}

			mockPwProvider := &MockPasswordProvider{}
			mockUserInt := &mockUserInteraction{
				confirmResponse: tc.confirmResponse,
				confirmErr:      tc.confirmError,
			}

			application := app.NewApplication(
				"", &MockLogger{}, mockCfgLoader, mockStore, nil,
				mockPwProvider, mockUserInt, &MockCommander{}, nil,
				&mockIdentityProviderFactory{}, &mockCryptoServiceFactory{}, &mockValidationService{},
			)

			// Run the method
			var pruned []string
			var err error
			testutil.WithSilentOutput(t, func() {
				pruned, err = application.CleanHosts(context.Background(), tc.force)
			})

			// Assertions
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}

			if len(pruned) != len(tc.expectedPruned) {
				t.Fatalf("expected %d pruned hosts, got %d", len(tc.expectedPruned), len(pruned))
			}

			if tc.expectStoreDelete {
				if len(mockStore.deletedIDs) != len(tc.expectedPruned) {
					t.Errorf("expected %d calls to store.DeleteHost, got %d", len(tc.expectedPruned), len(mockStore.deletedIDs))
				}
			} else {
				if len(mockStore.deletedIDs) > 0 {
					t.Errorf("expected no calls to store.DeleteHost, but got %d", len(mockStore.deletedIDs))
				}
			}
		})
	}
}

type mockIdentityProvider struct {
	validateError error
}

func (m *mockIdentityProvider) GetIdentity() (age.Identity, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return &mockAgeIdentity{}, nil
}

func (m *mockIdentityProvider) GetRecipients() ([]age.Recipient, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return []age.Recipient{&mockAgeRecipient{}}, nil
}

func (m *mockIdentityProvider) Validate() error {
	return m.validateError
}

type mockAgeIdentity struct {
	validateError error
}

func (m *mockAgeIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return []byte("mock-file-key-1234567890123456"), nil
}

type mockAgeRecipient struct {
	validateError error
}

func (m *mockAgeRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return []*age.Stanza{{Type: "mock", Args: []string{"test"}, Body: []byte("mock-body")}}, nil
}

type mockIdentityProviderFactory struct{}

func (m *mockIdentityProviderFactory) CreateIdentityProvider(cfg *domain.CAConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	return &mockIdentityProvider{}, nil
}

func (m *mockIdentityProviderFactory) CreateHostIdentityProvider(cfg *domain.CAConfig, hostCfg *domain.HostConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	return &mockIdentityProvider{}, nil
}

type mockCryptoServiceFactory struct {
	cryptoSvc domain.CryptoService
}

func (m *mockCryptoServiceFactory) CreateCryptoService(identityProvider domain.IdentityProvider) domain.CryptoService {
	if m.cryptoSvc != nil {
		return m.cryptoSvc
	}
	return &MockCryptoService{}
}

type mockValidationService struct {
	validateError error
}

func (m *mockValidationService) ValidateProviderRoundTrip(provider domain.IdentityProvider) error {
	return m.validateError
}

// --- Test Helpers ---

// TestMode represents different test configuration modes for createTestApp
type TestMode int

const (
	TestModePassword TestMode = iota
	TestModeSSHValid
	TestModeSSHInvalidIdentity
	TestModeSSHMismatchedRecipients
	TestModePlugin
)

func generateTestKey() crypto.Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func createTestDir(t *testing.T) string {
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	err := os.MkdirAll(storeDir, 0755)
	if err != nil {
		t.Fatalf("failed to create test store directory: %v", err)
	}
	return tmpDir
}

func generateEd25519TestKey(keyPath string) error {
	cmd := []string{"ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "test@example.com"}
	return runCommand(cmd...)
}

func runCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}

func setupSSHKeys(t *testing.T, testRoot string, mode TestMode) domain.SSHConfig {
	switch mode {
	case TestModeSSHValid:
		sshKeyFile := filepath.Join(testRoot, "id_ed25519")
		sshPubKeyFile := filepath.Join(testRoot, "id_ed25519.pub")
		if err := generateEd25519TestKey(sshKeyFile); err != nil {
			t.Fatalf("failed to generate test SSH key: %v", err)
		}
		pubKeyBytes, err := os.ReadFile(sshPubKeyFile)
		if err != nil {
			t.Fatalf("failed to read SSH public key: %v", err)
		}
		return domain.SSHConfig{
			IdentityFile: sshKeyFile,
			Recipients:   []string{string(pubKeyBytes)},
		}

	case TestModeSSHInvalidIdentity, TestModeSSHMismatchedRecipients:
		sshKeyFile1 := filepath.Join(testRoot, "id_ed25519_1")
		sshKeyFile2 := filepath.Join(testRoot, "id_ed25519_2")
		sshPubKeyFile2 := filepath.Join(testRoot, "id_ed25519_2.pub")
		if err := generateEd25519TestKey(sshKeyFile1); err != nil {
			t.Fatalf("failed to generate test SSH key 1: %v", err)
		}
		if err := generateEd25519TestKey(sshKeyFile2); err != nil {
			t.Fatalf("failed to generate test SSH key 2: %v", err)
		}
		pubKeyBytes, err := os.ReadFile(sshPubKeyFile2)
		if err != nil {
			t.Fatalf("failed to read SSH public key 2: %v", err)
		}
		return domain.SSHConfig{
			IdentityFile: sshKeyFile1,
			Recipients:   []string{string(pubKeyBytes)},
		}

	default:
		return domain.SSHConfig{}
	}
}

func setupPluginConfig(t *testing.T, testRoot string) domain.PluginConfig {
	// Create mock plugin identity
	identityFile := filepath.Join(testRoot, "plugin_identity.txt")
	mockIdentityData := []byte("AGE-PLUGIN-TEST-1Q2FHQTVK4W7RQVHX2LQGZ8LQGZ8LQGZ8LQGZ8LQGZ8LQG")
	if err := os.WriteFile(identityFile, mockIdentityData, 0600); err != nil {
		t.Fatalf("failed to create mock plugin identity: %v", err)
	}

	return domain.PluginConfig{
		IdentityFile: identityFile,
		Recipients: []string{
			"age1test2fhqtvk4w7rqvhx2lqgz8lqgz8lqgz8lqgz8lqgz8lqg",
		},
	}
}

type testAppConfig struct {
	mode        TestMode
	keyPaths    []string
	mockOptions map[string]interface{}
}

func createTestApp(t *testing.T, config testAppConfig) (*app.Application, *mockStore, string) {
	testRoot := createTestDir(t)

	// Create mock key files
	absolutePaths := make([]string, len(config.keyPaths))
	for i, path := range config.keyPaths {
		absolutePaths[i] = filepath.Join(testRoot, path)
		dir := filepath.Dir(absolutePaths[i])
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
		mockKeyContent := []byte("mock-encrypted-key-data-" + filepath.Base(path))
		if err := os.WriteFile(absolutePaths[i], mockKeyContent, 0600); err != nil {
			t.Fatalf("failed to create mock key file %s: %v", absolutePaths[i], err)
		}
	}

	// Setup CA config
	cfg := &domain.CAConfig{
		Encryption: domain.EncryptionConfig{
			Password: domain.PasswordConfig{MinLength: 8},
		},
	}

	switch config.mode {
	case TestModePassword:
		cfg.Encryption.Provider = "password"
	case TestModeSSHValid, TestModeSSHInvalidIdentity, TestModeSSHMismatchedRecipients:
		cfg.Encryption.Provider = "ssh"
		cfg.Encryption.SSH = setupSSHKeys(t, testRoot, config.mode)
	case TestModePlugin:
		cfg.Encryption.Provider = "plugin"
		cfg.Encryption.Plugin = setupPluginConfig(t, testRoot)
	default:
		t.Fatalf("unknown test mode: %d", config.mode)
	}

	// Setup mocks
	mockStore := &mockStore{
		encryptedKeyPaths: absolutePaths,
		keyData:           make(map[string][]byte),
	}
	if updateError, ok := config.mockOptions["updateKeyError"]; ok {
		mockStore.updateKeyError = updateError.(error)
	}

	mockCrypto := &MockCryptoService{}
	if decryptError, ok := config.mockOptions["decryptError"]; ok {
		mockCrypto.DecryptPrivateKeyFunc = func(pemData []byte) (crypto.Signer, error) {
			return nil, decryptError.(error)
		}
	} else {
		mockCrypto.DecryptPrivateKeyFunc = func(pemData []byte) (crypto.Signer, error) {
			return generateTestKey(), nil
		}
	}
	mockCrypto.EncryptPrivateKeyFunc = func(key crypto.Signer) ([]byte, error) {
		pub := key.Public().(*ecdsa.PublicKey)
		return []byte(fmt.Sprintf("encrypted-key-%x", pub.X.Bytes())), nil
	}

	mockUserInt := &mockUserInteraction{confirmResponse: true}
	if confirmResponse, ok := config.mockOptions["confirmResponse"]; ok {
		mockUserInt.confirmResponse = confirmResponse.(bool)
	}

	mockValidation := &mockValidationService{}
	if validateError, ok := config.mockOptions["validateError"]; ok {
		mockValidation.validateError = validateError.(error)
	}

	mockPwProvider := &MockPasswordProvider{MasterPassword: []byte("old-password")}
	if newPassword, ok := config.mockOptions["newPassword"]; ok {
		mockPwProvider.MasterPassword = newPassword.([]byte)
	}
	mockCfgLoader := &MockConfigLoader{CAConfig: cfg}

	// Create factories that can produce different types of providers/services based on test mode
	mockIdentityFactory := &mockIdentityProviderFactory{}
	mockCryptoFactory := &mockCryptoServiceFactory{cryptoSvc: mockCrypto}

	application := app.NewApplication(
		testRoot, &MockLogger{}, mockCfgLoader, mockStore, mockCrypto,
		mockPwProvider, mockUserInt, &MockCommander{}, nil,
		mockIdentityFactory, mockCryptoFactory, mockValidation,
	)

	return application, mockStore, testRoot
}

// --- ReencryptKeys Tests ---

func TestReencryptKeys_PasswordChange_Success(t *testing.T) {
	keyPaths := []string{
		"store/ca/ca.key.age",
		"store/hosts/web1/cert.key.age",
		"store/hosts/web2/cert.key.age",
	}

	app, mockStore, testRoot := createTestApp(t, testAppConfig{
		mode:        TestModePassword,
		keyPaths:    keyPaths,
		mockOptions: map[string]interface{}{},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Assertions
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify all keys were re-encrypted
	if len(mockStore.keyData) != 3 {
		t.Errorf("expected 3 keys to be re-encrypted, got %d", len(mockStore.keyData))
	}

	// Verify specific paths were updated
	expectedPaths := []string{
		filepath.Join(testRoot, "store/ca/ca.key.age"),
		filepath.Join(testRoot, "store/hosts/web1/cert.key.age"),
		filepath.Join(testRoot, "store/hosts/web2/cert.key.age"),
	}
	for _, path := range expectedPaths {
		if _, exists := mockStore.keyData[path]; !exists {
			t.Errorf("expected key path %s to be updated", path)
		}
	}
}

func TestReencryptKeys_PasswordChange_WrongOldPassword(t *testing.T) {
	keyPaths := []string{"store/ca/ca.key.age"}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:     TestModePassword,
		keyPaths: keyPaths,
		mockOptions: map[string]interface{}{
			"decryptError": domain.ErrIncorrectPassword,
		},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Assertions
	if !errors.Is(err, domain.ErrIncorrectPassword) {
		t.Errorf("expected ErrIncorrectPassword, got %v", err)
	}

	// Verify no keys were updated
	if len(mockStore.keyData) != 0 {
		t.Errorf("expected no keys to be updated on failure, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_AgeSsh_UserNotInRecipients_Warning(t *testing.T) {
	keyPaths := []string{"store/ca/ca.key.age"}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:     TestModeSSHMismatchedRecipients,
		keyPaths: keyPaths,
		mockOptions: map[string]interface{}{
			"validateError":   errors.New("SSH identity not found in recipients"),
			"confirmResponse": true,
		},
	})

	// Execute without force flag - should prompt user
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should succeed because user confirmed
	if err != nil {
		t.Errorf("expected operation to succeed after user confirmation, got %v", err)
	}

	// Verify key was re-encrypted despite validation failure
	if len(mockStore.keyData) != 1 {
		t.Errorf("expected 1 key to be re-encrypted, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_AgeSsh_ValidationFailure_UserDeclines(t *testing.T) {
	keyPaths := []string{"store/ca/ca.key.age"}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:     TestModeSSHInvalidIdentity,
		keyPaths: keyPaths,
		mockOptions: map[string]interface{}{
			"validateError":   errors.New("round-trip validation failed"),
			"confirmResponse": false,
		},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should fail because user declined
	if err == nil {
		t.Error("expected operation to fail when user declines")
		return
	}
	if err.Error() != "operation cancelled by user" {
		t.Errorf("expected operation cancelled error, got %v", err)
	}

	// Verify no keys were updated
	if len(mockStore.keyData) != 0 {
		t.Errorf("expected no keys to be updated when user declines, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_AgeSsh_ValidRecipients_Success(t *testing.T) {
	keyPaths := []string{
		"store/ca/ca.key.age",
		"store/hosts/server1/cert.key.age",
	}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:        TestModeSSHValid,
		keyPaths:    keyPaths,
		mockOptions: map[string]interface{}{},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should succeed without prompts
	if err != nil {
		t.Errorf("expected success with valid recipients, got %v", err)
	}

	// Verify keys were re-encrypted
	if len(mockStore.keyData) != 2 {
		t.Errorf("expected 2 keys to be re-encrypted, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_AgeSsh_RoundTripFailure_ForceSkip(t *testing.T) {
	keyPaths := []string{"store/ca/ca.key.age"}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:     TestModeSSHInvalidIdentity,
		keyPaths: keyPaths,
		mockOptions: map[string]interface{}{
			"validateError": errors.New("round-trip validation failed"),
		},
	})

	// Execute with force=true to skip validation
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), true, false)
	})

	// Should succeed because validation was skipped
	if err != nil {
		t.Errorf("expected success with force flag, got %v", err)
	}

	// Verify key was re-encrypted despite validation failure
	if len(mockStore.keyData) != 1 {
		t.Errorf("expected 1 key to be re-encrypted, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_Plugin_Success(t *testing.T) {
	keyPaths := []string{
		"store/ca/ca.key.age",
		"store/hosts/device1/cert.key.age",
	}

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:        TestModePlugin,
		keyPaths:    keyPaths,
		mockOptions: map[string]interface{}{},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should succeed
	if err != nil {
		t.Errorf("expected success with plugin provider, got %v", err)
	}

	// Verify keys were re-encrypted
	if len(mockStore.keyData) != 2 {
		t.Errorf("expected 2 keys to be re-encrypted, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_NoKeysToReencrypt(t *testing.T) {
	keyPaths := []string{} // No keys to re-encrypt

	app, mockStore, _ := createTestApp(t, testAppConfig{
		mode:        TestModePassword,
		keyPaths:    keyPaths,
		mockOptions: map[string]interface{}{},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should succeed with no keys to process
	if err != nil {
		t.Errorf("expected success with no keys, got %v", err)
	}

	// Verify no keys were processed
	if len(mockStore.keyData) != 0 {
		t.Errorf("expected no keys to be processed, got %d", len(mockStore.keyData))
	}
}

func TestReencryptKeys_PartialFailure_StoreUpdateError(t *testing.T) {
	keyPaths := []string{"store/ca/ca.key.age"}

	app, _, _ := createTestApp(t, testAppConfig{
		mode:     TestModePassword,
		keyPaths: keyPaths,
		mockOptions: map[string]interface{}{
			"updateKeyError": errors.New("disk full"),
		},
	})

	// Execute
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.ReencryptKeys(context.Background(), false, false)
	})

	// Should fail on store update
	if err == nil {
		t.Error("expected failure on store update error")
	}

	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("expected disk full error in chain, got %v", err)
	}
}

func TestInfoCA(t *testing.T) {
	// Create a simple test certificate manually
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	testCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	// Setup test app with mock store
	testApp, mockStore, _ := createTestApp(t, testAppConfig{
		mode: TestModePassword,
	})

	// Configure mock store to return our test certificate
	mockStore.caCert = testCert

	// Execute
	cert, err := testApp.InfoCA(context.Background())

	// Verify
	if err != nil {
		t.Fatalf("InfoCA() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("InfoCA() returned nil certificate")
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("expected CommonName 'Test CA', got %q", cert.Subject.CommonName)
	}
}

// Note: ResolveHostConfig testing deferred due to complex config loader dependencies
