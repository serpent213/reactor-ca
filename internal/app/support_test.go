package app_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
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
	ExecuteFunc            func(name string, args ...string) ([]byte, error)
	ExecuteInteractiveFunc func(name string, args ...string) error
}

func (m *MockCommander) Execute(name string, args ...string) ([]byte, error) {
	if m.ExecuteFunc != nil {
		return m.ExecuteFunc(name, args...)
	}
	return []byte("ok"), nil
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
			Subject       domain.SubjectConfig `yaml:"subject"`
			Validity      domain.Validity      `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm  `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm `yaml:"hash_algorithm"`
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
			Subject       domain.SubjectConfig `yaml:"subject"`
			Validity      domain.Validity      `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm  `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm `yaml:"hash_algorithm"`
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
