//go:build !integration && !e2e

package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/testutil"
)

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
				&MockClock{},
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
