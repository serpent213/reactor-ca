package app_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/domain"
	cryptosvc "reactor.de/reactor-ca/internal/infra/crypto"
)

// --- Mocks for Dependencies ---

type MockConfigLoader struct {
	CAConfig    *domain.CAConfig
	HostsConfig *domain.HostsConfig
	Err         error
}

func (m *MockConfigLoader) LoadCA() (*domain.CAConfig, error)       { return m.CAConfig, m.Err }
func (m *MockConfigLoader) LoadHosts() (*domain.HostsConfig, error) { return m.HostsConfig, m.Err }
func (m *MockConfigLoader) ValidateCAConfig(data []byte) error      { return m.Err }
func (m *MockConfigLoader) ValidateHostsConfig(data []byte) error   { return m.Err }

type MockStore struct {
	SaveCAFunc             func(cert, key []byte) error
	SaveHostCertFunc       func(hostID string, cert []byte) error
	SaveHostKeyFunc        func(hostID string, encryptedKey []byte) error
	LoadCACertFunc         func() (*x509.Certificate, error)
	LoadHostCertFunc       func(hostID string) (*x509.Certificate, error)
	LoadHostKeyFunc        func(hostID string) ([]byte, error)
	HostKeyExistsMap       map[string]bool
	HostKeyExistsErr       error
	DeleteHostFunc         func(hostID string) error
	ListHostIDsFunc        func() ([]string, error)
	GetAllKeysFunc         func() ([]string, error)
	UpdateEncryptedKeyFunc func(path string, data []byte) error
}

func (m *MockStore) CAExists() (bool, error)                { return false, nil }
func (m *MockStore) SaveCA(c, k []byte) error               { return m.SaveCAFunc(c, k) }
func (m *MockStore) LoadCACert() (*x509.Certificate, error) { return m.LoadCACertFunc() }
func (m *MockStore) LoadCAKey() ([]byte, error)             { return nil, nil }
func (m *MockStore) HostExists(hostID string) (bool, error) { return false, nil }
func (m *MockStore) HostKeyExists(hostID string) (bool, error) {
	return m.HostKeyExistsMap[hostID], m.HostKeyExistsErr
}
func (m *MockStore) HostCertExists(hostID string) (bool, error) {
	return false, nil
}
func (m *MockStore) SaveHostCert(id string, c []byte) error            { return m.SaveHostCertFunc(id, c) }
func (m *MockStore) SaveHostKey(id string, k []byte) error             { return m.SaveHostKeyFunc(id, k) }
func (m *MockStore) LoadHostCert(id string) (*x509.Certificate, error) { return m.LoadHostCertFunc(id) }
func (m *MockStore) LoadHostKey(id string) ([]byte, error)             { return m.LoadHostKeyFunc(id) }
func (m *MockStore) ListHostIDs() ([]string, error)                    { return m.ListHostIDsFunc() }
func (m *MockStore) DeleteHost(id string) error                        { return m.DeleteHostFunc(id) }
func (m *MockStore) GetAllEncryptedKeyPaths() ([]string, error)        { return m.GetAllKeysFunc() }
func (m *MockStore) UpdateEncryptedKey(p string, d []byte) error {
	return m.UpdateEncryptedKeyFunc(p, d)
}
func (m *MockStore) GetHostCertPath(id string) string { return "" }
func (m *MockStore) GetHostKeyPath(id string) string  { return "" }
func (m *MockStore) GetCACertPath() string            { return "" }

// Backup operations - mock implementations
func (m *MockStore) CreateBackupFile(originalPath string) error  { return nil }
func (m *MockStore) RestoreFromBackup(originalPath string) error { return nil }
func (m *MockStore) RemoveBackupFile(originalPath string) error  { return nil }

type MockCryptoService struct {
	GeneratePrivateKeyFunc     func(algo domain.KeyAlgorithm) (crypto.Signer, error)
	CreateRootCertificateFunc  func(cfg *domain.CAConfig, key crypto.Signer) (*x509.Certificate, error)
	CreateHostCertificateFunc  func(hostCfg *domain.HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error)
	SignCSRFunc                func(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error)
	EncryptPrivateKeyFunc      func(key crypto.Signer) ([]byte, error)
	DecryptPrivateKeyFunc      func(pemData []byte) (crypto.Signer, error)
	EncodeCertificateToPEMFunc func(cert *x509.Certificate) []byte
	EncodeKeyToPEMFunc         func(key crypto.Signer) ([]byte, error)
	ParseCertificateFunc       func(pemData []byte) (*x509.Certificate, error)
	ParsePrivateKeyFunc        func(pemData []byte) (crypto.Signer, error)
	ParseCSRFunc               func(pemData []byte) (*x509.CertificateRequest, error)
	ValidateKeyPairFunc        func(cert *x509.Certificate, key crypto.Signer) error
}

func (m *MockCryptoService) GeneratePrivateKey(a domain.KeyAlgorithm) (crypto.Signer, error) {
	return m.GeneratePrivateKeyFunc(a)
}
func (m *MockCryptoService) CreateRootCertificate(cfg *domain.CAConfig, key crypto.Signer) (*x509.Certificate, error) {
	return m.CreateRootCertificateFunc(cfg, key)
}
func (m *MockCryptoService) CreateHostCertificate(h *domain.HostConfig, c *x509.Certificate, k crypto.Signer, p crypto.PublicKey) (*x509.Certificate, error) {
	return m.CreateHostCertificateFunc(h, c, k, p)
}
func (m *MockCryptoService) SignCSR(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error) {
	return m.SignCSRFunc(csr, caCert, caKey, validityDays)
}
func (m *MockCryptoService) EncryptPrivateKey(k crypto.Signer) ([]byte, error) {
	return m.EncryptPrivateKeyFunc(k)
}
func (m *MockCryptoService) DecryptPrivateKey(d []byte) (crypto.Signer, error) {
	return m.DecryptPrivateKeyFunc(d)
}
func (m *MockCryptoService) EncodeCertificateToPEM(c *x509.Certificate) []byte {
	return m.EncodeCertificateToPEMFunc(c)
}
func (m *MockCryptoService) EncodeKeyToPEM(key crypto.Signer) ([]byte, error) {
	return m.EncodeKeyToPEMFunc(key)
}
func (m *MockCryptoService) ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	return m.ParseCertificateFunc(pemData)
}
func (m *MockCryptoService) ParsePrivateKey(pemData []byte) (crypto.Signer, error) {
	return m.ParsePrivateKeyFunc(pemData)
}
func (m *MockCryptoService) ParseCSR(pemData []byte) (*x509.CertificateRequest, error) {
	return m.ParseCSRFunc(pemData)
}
func (m *MockCryptoService) ValidateKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	return m.ValidateKeyPairFunc(cert, key)
}

type MockPasswordProvider struct {
	MasterPassword    []byte
	MasterPasswordErr error
}

func (m *MockPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return m.MasterPassword, m.MasterPasswordErr
}
func (m *MockPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}
func (m *MockPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}

type MockCommander struct {
	ExecuteInteractiveFunc func(name string, args ...string) error
}

func (m *MockCommander) ExecuteInteractive(name string, args ...string) error {
	if m.ExecuteInteractiveFunc != nil {
		return m.ExecuteInteractiveFunc(name, args...)
	}
	return nil
}

type MockLogger struct{}

func (m *MockLogger) Info(msg string, args ...interface{})    {}
func (m *MockLogger) Error(msg string, args ...interface{})   {}
func (m *MockLogger) Warning(msg string, args ...interface{}) {}
func (m *MockLogger) Log(msg string)                          {}

type MockIdentityProviderFactory struct {
	CreateIdentityProviderFunc     func(*domain.CAConfig, domain.PasswordProvider) (domain.IdentityProvider, error)
	CreateHostIdentityProviderFunc func(*domain.CAConfig, *domain.HostConfig, domain.PasswordProvider) (domain.IdentityProvider, error)
}

func (m *MockIdentityProviderFactory) CreateIdentityProvider(cfg *domain.CAConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	if m.CreateIdentityProviderFunc != nil {
		return m.CreateIdentityProviderFunc(cfg, passwordProvider)
	}
	return &MockIdentityProvider{}, nil
}

func (m *MockIdentityProviderFactory) CreateHostIdentityProvider(cfg *domain.CAConfig, hostCfg *domain.HostConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	if m.CreateHostIdentityProviderFunc != nil {
		return m.CreateHostIdentityProviderFunc(cfg, hostCfg, passwordProvider)
	}
	// Default to base provider behavior for compatibility
	return m.CreateIdentityProvider(cfg, passwordProvider)
}

type MockIdentityProvider struct {
	GetRecipientsFunc func() ([]age.Recipient, error)
	GetIdentityFunc   func() (age.Identity, error)
	ValidateFunc      func() error
}

func (m *MockIdentityProvider) GetRecipients() ([]age.Recipient, error) {
	if m.GetRecipientsFunc != nil {
		return m.GetRecipientsFunc()
	}
	return []age.Recipient{}, nil
}

func (m *MockIdentityProvider) GetIdentity() (age.Identity, error) {
	if m.GetIdentityFunc != nil {
		return m.GetIdentityFunc()
	}
	return nil, nil
}

func (m *MockIdentityProvider) Validate() error {
	if m.ValidateFunc != nil {
		return m.ValidateFunc()
	}
	return nil
}

type MockCryptoServiceFactory struct {
	CreateCryptoServiceFunc func(domain.IdentityProvider) domain.CryptoService
}

func (m *MockCryptoServiceFactory) CreateCryptoService(identityProvider domain.IdentityProvider) domain.CryptoService {
	if m.CreateCryptoServiceFunc != nil {
		return m.CreateCryptoServiceFunc(identityProvider)
	}
	// Return a default crypto service mock
	return &MockCryptoService{}
}

// --- Test Setup Helper ---

// Mocks contains all the mockable dependencies for the Application.
type Mocks struct {
	ConfigLoader            *MockConfigLoader
	Store                   *MockStore
	CryptoSvc               *MockCryptoService
	Password                *MockPasswordProvider
	Commander               *MockCommander
	Logger                  *MockLogger
	IdentityProviderFactory *MockIdentityProviderFactory
	CryptoServiceFactory    *MockCryptoServiceFactory
}

// SetupTestApplication initializes the Application service with mocks for unit testing.
func SetupTestApplication(t *testing.T) (*app.Application, *Mocks) {
	t.Helper()

	// Use real crypto service for cert generation, but allow overriding specific functions.
	// This makes it easy to test logic without mocking all of crypto.
	realCryptoSvc := cryptosvc.NewService()

	mockCryptoServiceFactory := &MockCryptoServiceFactory{}
	mockIdentityProviderFactory := &MockIdentityProviderFactory{}

	// Set up the crypto service factory to return the mock crypto service
	mockCryptoSvc := &MockCryptoService{
		GeneratePrivateKeyFunc:     realCryptoSvc.GeneratePrivateKey,
		CreateRootCertificateFunc:  realCryptoSvc.CreateRootCertificate,
		CreateHostCertificateFunc:  realCryptoSvc.CreateHostCertificate,
		SignCSRFunc:                realCryptoSvc.SignCSR,
		EncodeCertificateToPEMFunc: realCryptoSvc.EncodeCertificateToPEM,
		EncodeKeyToPEMFunc:         realCryptoSvc.EncodeKeyToPEM,
		ParseCertificateFunc:       realCryptoSvc.ParseCertificate,
		ParsePrivateKeyFunc:        realCryptoSvc.ParsePrivateKey,
		ParseCSRFunc:               realCryptoSvc.ParseCSR,
		ValidateKeyPairFunc:        realCryptoSvc.ValidateKeyPair,
		// EncryptPrivateKeyFunc and DecryptPrivateKeyFunc left nil - tests must set these
	}
	mockCryptoServiceFactory.CreateCryptoServiceFunc = func(identityProvider domain.IdentityProvider) domain.CryptoService {
		return mockCryptoSvc
	}

	mocks := &Mocks{
		ConfigLoader:            &MockConfigLoader{},
		Store:                   &MockStore{},
		CryptoSvc:               mockCryptoSvc,
		Password:                &MockPasswordProvider{},
		Commander:               &MockCommander{},
		Logger:                  &MockLogger{},
		IdentityProviderFactory: mockIdentityProviderFactory,
		CryptoServiceFactory:    mockCryptoServiceFactory,
	}

	application := app.NewApplication(
		"/test/root",
		mocks.Logger,
		mocks.ConfigLoader,
		mocks.Store,
		mocks.CryptoSvc,
		mocks.Password,
		nil, // UserInteraction
		mocks.Commander,
		nil, // IdentityProvider
		mocks.IdentityProviderFactory,
		mocks.CryptoServiceFactory,
		nil, // ValidationService
	)

	return application, mocks
}

// --- Common Test Data ---

func GetTestCAConfig() *domain.CAConfig {
	return &domain.CAConfig{
		CA: struct {
			Subject       domain.SubjectConfig    `yaml:"subject"`
			Validity      domain.Validity         `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm     `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm    `yaml:"hash_algorithm"`
			Extensions    domain.ExtensionsConfig `yaml:"extensions,omitempty"`
		}{
			Subject:      domain.SubjectConfig{CommonName: "Test CA"},
			Validity:     domain.Validity{Years: 1},
			KeyAlgorithm: domain.ECP256,
		},
		Encryption: domain.EncryptionConfig{Provider: "password"},
	}
}

func GetTestHostsConfig(hostID string) *domain.HostsConfig {
	return &domain.HostsConfig{
		Hosts: map[string]domain.HostConfig{
			hostID: {
				Subject:      domain.SubjectConfig{CommonName: hostID + ".test.com"},
				Validity:     domain.Validity{Days: 90},
				KeyAlgorithm: domain.RSA2048,
			},
		},
	}
}

func GetTestCACert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	// Use the real crypto service to generate a valid CA cert for tests
	svc := cryptosvc.NewService()
	key, err := svc.GeneratePrivateKey(domain.ECP256)
	if err != nil {
		t.Fatalf("Failed to generate test CA key: %v", err)
	}
	cert, err := svc.CreateRootCertificate(&domain.CAConfig{
		CA: struct {
			Subject       domain.SubjectConfig    `yaml:"subject"`
			Validity      domain.Validity         `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm     `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm    `yaml:"hash_algorithm"`
			Extensions    domain.ExtensionsConfig `yaml:"extensions,omitempty"`
		}{
			Subject:  domain.SubjectConfig{CommonName: "Test CA"},
			Validity: domain.Validity{Years: 1},
		},
	}, key)
	if err != nil {
		t.Fatalf("Failed to generate test CA cert: %v", err)
	}
	return cert, key
}

func GetTestError() error {
	return errors.New("something went wrong")
}

var DummyPassword = []byte("test-password")
var DummyEncryptedKey = []byte("age-encrypted-key-data")
var DummyCertPEM = []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

// --- Additional Mocks from application_test.go ---

type mockUserInteraction struct {
	confirmResponse bool
	confirmErr      error
}

func (m *mockUserInteraction) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, m.confirmErr
}

type mockValidationService struct {
	validateError error
}

func (m *mockValidationService) ValidateProviderRoundTrip(provider domain.IdentityProvider) error {
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

// --- Test Helper Functions ---

// TestMode represents different test configuration modes
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

// --- Additional Mock Types for ReencryptKeys Tests ---

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
