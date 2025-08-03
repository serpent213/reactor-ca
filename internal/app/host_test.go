//go:build !integration && !e2e

package app_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"reactor.de/reactor-ca/internal/domain"
	cryptosvc "reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/testutil"
)

func TestIssueHost_NewHost(t *testing.T) {
	// Arrange
	const hostID = "web-server"
	app, mocks := SetupTestApplication(t)
	testCAConfig := GetTestCAConfig()
	testHostsConfig := GetTestHostsConfig(hostID)
	testCACert, testCAKey := GetTestCACert(t)

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) {
		return testCACert, nil
	}
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: false} // Key does not exist
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		// Use real crypto service for this
		return cryptosvc.NewService(&MockClock{}).GeneratePrivateKey(algo)
	}
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(key crypto.Signer) ([]byte, error) {
		return DummyEncryptedKey, nil
	}
	mocks.Store.SaveHostKeyFunc = func(id string, encryptedKey []byte) error {
		if id != hostID {
			t.Errorf("expected to save key for host '%s', got '%s'", hostID, id)
		}
		if string(encryptedKey) != string(DummyEncryptedKey) {
			t.Errorf("unexpected encrypted key data saved")
		}
		return nil
	}
	mocks.Store.SaveHostCertFunc = func(id string, cert []byte) error {
		if id != hostID {
			t.Errorf("expected to save cert for host '%s', got '%s'", hostID, id)
		}
		return nil
	}
	// Use real function to decrypt the CA key
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d []byte) (crypto.Signer, error) { return testCAKey, nil }

	// Act
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.IssueHost(context.Background(), hostID, false, false)
	})

	// Assert
	if err != nil {
		t.Fatalf("IssueHost failed: %v", err)
	}
	// Assertions are performed inside the mock functions
}

func TestIssueHost_RenewHost(t *testing.T) {
	// Arrange
	const hostID = "db-server"
	app, mocks := SetupTestApplication(t)
	testCAConfig := GetTestCAConfig()
	testHostsConfig := GetTestHostsConfig(hostID)
	testCACert, testCAKey := GetTestCACert(t)
	// Use real crypto service to generate a realistic host key
	realCrypto := cryptosvc.NewService(&MockClock{})
	existingHostKey, _ := realCrypto.GeneratePrivateKey(domain.ECP256)

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: true} // Key EXISTS
	mocks.Store.LoadHostKeyFunc = func(id string) ([]byte, error) {
		return DummyEncryptedKey, nil // Return some dummy encrypted data
	}
	// Decrypt should return our known host key
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(data []byte) (crypto.Signer, error) {
		// The first call will be to decrypt the CA key, second for the host key
		if string(data) == string(DummyEncryptedKey) {
			return existingHostKey, nil
		}
		return testCAKey, nil
	}
	var generatedKeyForRekey crypto.Signer
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		// This should NOT be called when renewing without --rekey
		t.Error("GeneratePrivateKey should not be called when renewing an existing host")
		// but we still return a value to not panic
		generatedKeyForRekey, _ = realCrypto.GeneratePrivateKey(algo)
		return generatedKeyForRekey, nil
	}
	mocks.Store.SaveHostCertFunc = func(id string, cert []byte) error { return nil } // We expect this to be called

	// Act
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.IssueHost(context.Background(), hostID, false, false) // rekey=false
	})

	// Assert
	if err != nil {
		t.Fatalf("IssueHost for renewal failed: %v", err)
	}
	if generatedKeyForRekey != nil {
		t.Error("A new key was generated for a simple renewal, which is incorrect.")
	}
}

func TestIssueHost_RekeyHost(t *testing.T) {
	// Arrange
	const hostID = "api-server"
	app, mocks := SetupTestApplication(t)
	testCAConfig := GetTestCAConfig()
	testHostsConfig := GetTestHostsConfig(hostID)
	testCACert, testCAKey := GetTestCACert(t)
	realCrypto := cryptosvc.NewService(&MockClock{})
	var newKeyGenerated bool

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: true} // Key exists, but we will rekey
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		newKeyGenerated = true
		return realCrypto.GeneratePrivateKey(algo)
	}
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(k crypto.Signer) ([]byte, error) { return DummyEncryptedKey, nil }
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d []byte) (crypto.Signer, error) { return testCAKey, nil } // Only CA key is decrypted
	mocks.Store.SaveHostKeyFunc = func(id string, k []byte) error { return nil }
	mocks.Store.SaveHostCertFunc = func(id string, c []byte) error { return nil }

	// Act
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.IssueHost(context.Background(), hostID, true, false) // rekey=true
	})

	// Assert
	if err != nil {
		t.Fatalf("IssueHost with rekey failed: %v", err)
	}
	if !newKeyGenerated {
		t.Error("Expected a new key to be generated with --rekey, but it wasn't")
	}
}

func TestIssueHost_Deploy(t *testing.T) {
	// Arrange
	const hostID = "deploy-target"
	app, mocks := SetupTestApplication(t)
	testCAConfig := GetTestCAConfig()
	testHostsConfig := GetTestHostsConfig(hostID)
	// Add deploy commands to config
	testHostsConfig.Hosts[hostID] = domain.HostConfig{
		Subject:      domain.SubjectConfig{CommonName: "deploy.test.com"},
		Validity:     domain.Validity{Days: 1},
		KeyAlgorithm: domain.ECP256,
		Deploy:       domain.DeployConfig{Command: "echo deployed"},
	}
	testCACert, testCAKey := GetTestCACert(t)
	realCrypto := cryptosvc.NewService(&MockClock{})
	hostKey, _ := realCrypto.GeneratePrivateKey(domain.ECP256)
	var commanderCalled bool

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: false}
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(a domain.KeyAlgorithm) (crypto.Signer, error) { return hostKey, nil }
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(k crypto.Signer) ([]byte, error) { return DummyEncryptedKey, nil }
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d []byte) (crypto.Signer, error) {
		// 1st decrypt CA key, 2nd decrypt host key for deploy
		if string(d) == "" { // simple heuristic for test
			return testCAKey, nil
		}
		return hostKey, nil
	}
	mocks.Store.LoadHostCertFunc = func(id string) (*x509.Certificate, error) {
		// Create a valid certificate for deploy
		hostConfig := testHostsConfig.Hosts[hostID]
		return realCrypto.CreateHostCertificate(&hostConfig, testCACert, testCAKey, hostKey.Public())
	}
	mocks.Store.LoadHostKeyFunc = func(id string) ([]byte, error) { return DummyEncryptedKey, nil } // for deploy step
	mocks.Store.SaveHostKeyFunc = func(id string, k []byte) error { return nil }
	mocks.Store.SaveHostCertFunc = func(id string, c []byte) error { return nil }
	mocks.Commander.ExecuteInteractiveFunc = func(name string, args ...string) error {
		commanderCalled = true
		return nil
	}

	// Act
	var err error
	testutil.WithSilentOutput(t, func() {
		err = app.IssueHost(context.Background(), hostID, false, true) // deploy=true
	})

	// Assert
	if err != nil {
		t.Fatalf("IssueHost with deploy failed: %v", err)
	}
	if !commanderCalled {
		t.Error("Expected commander to be executed for deployment, but it wasn't")
	}
}
