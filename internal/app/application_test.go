package app_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/serpent213/reactor-ca/internal/app"
	"github.com/serpent213/reactor-ca/internal/domain"
)

// --- Mocks ---

type mockConfigLoader struct {
	ca    *domain.CAConfig
	hosts *domain.HostsConfig
	err   error
}

func (m *mockConfigLoader) LoadCA() (*domain.CAConfig, error) {
	return m.ca, m.err
}
func (m *mockConfigLoader) LoadHosts() (*domain.HostsConfig, error) {
	return m.hosts, m.err
}

type mockStore struct {
	hostIDs    []string
	deletedIDs []string
	err        error
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

// Add empty implementations for other Store methods to satisfy the interface
func (m *mockStore) CAExists() (bool, error)                              { return false, nil }
func (m *mockStore) SaveCA(cert, encryptedKey []byte) error               { return nil }
func (m *mockStore) LoadCACert() (*x509.Certificate, error)               { return nil, nil }
func (m *mockStore) LoadCAKey() ([]byte, error)                           { return nil, nil }
func (m *mockStore) HostExists(hostID string) (bool, error)               { return false, nil }
func (m *mockStore) HostKeyExists(hostID string) (bool, error)            { return false, nil }
func (m *mockStore) SaveHostCert(hostID string, cert []byte) error        { return nil }
func (m *mockStore) SaveHostKey(hostID string, encryptedKey []byte) error { return nil }
func (m *mockStore) LoadHostCert(hostID string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockStore) LoadHostKey(hostID string) ([]byte, error)  { return nil, nil }
func (m *mockStore) GetAllEncryptedKeyPaths() ([]string, error) { return nil, nil }
func (m *mockStore) UpdateEncryptedKey(path string, data []byte) error {
	return nil
}
func (m *mockStore) GetHostCertPath(hostID string) string { return "" }
func (m *mockStore) GetHostKeyPath(hostID string) string  { return "" }
func (m *mockStore) GetCACertPath() string                { return "" }

type mockPasswordProvider struct {
	confirmResponse bool
	confirmErr      error
}

func (m *mockPasswordProvider) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, m.confirmErr
}

// Add empty implementations for other PasswordProvider methods
func (m *mockPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}

type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...interface{})  {}
func (m *mockLogger) Error(msg string, args ...interface{}) {}
func (m *mockLogger) Log(msg string)                        {}

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
			mockCfgLoader := &mockConfigLoader{
				hosts: &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)},
			}
			for _, id := range tc.configIDs {
				mockCfgLoader.hosts.Hosts[id] = domain.HostConfig{}
			}

			mockStore := &mockStore{
				hostIDs: tc.storeIDs,
			}

			mockPwProvider := &mockPasswordProvider{
				confirmResponse: tc.confirmResponse,
				confirmErr:      tc.confirmError,
			}

			// Create Application instance
			application := app.NewApplication("", &mockLogger{}, mockCfgLoader, mockStore, nil, mockPwProvider, nil, nil)

			// Run the method
			pruned, err := application.CleanHosts(context.Background(), tc.force)

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
