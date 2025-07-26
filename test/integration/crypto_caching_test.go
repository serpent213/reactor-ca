//go:build integration

package integration

import (
	"crypto"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"reactor.de/reactor-ca/internal/domain"
	cryptoSvc "reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/identity"
)

// Test data using real age-plugin-se values (test-only keys, safe to share)
const (
	// Real age-plugin-se identity and recipient for testing
	testPluginIdentity  = "AGE-PLUGIN-SE-1QJPQZD33SGQNYVYP75XQYUNTXXQ7UVQTPSPKY6TYQSZDXVU69CCYSRQRWP6KYPZPQ3GTDTGSK5HTC2ZJX228PZ7VHEMU8RUQFZMWTKNPT8K9TJ9K4X4WG4VT3F7KDS4E4U6E46URYZKHF8ZLYHJTQ0M5TWFGWYH4ACWZAQNQXQYQCQMJDDHSYQGQXQRSCQNTWSPQZPPS9CXQYAMTQS5FNHLFXXDXSYKQTUUMMTG2NL89U7KWRN06HUHURFGW9Q0Q4H6007FXRJ8WL494RP2NQPCVQF3XXQSPPYCQWRQZDDMQYQGZXQTSCQMTD9JQGY90WFQ42C2TGSMTGHDXHENZTJ2MXQNSCQMJDDKSGGQAJN26GMDYGHF4DQHS4DKEXKYNX7ZZX7GH6QDPA9HL077RTXXLMVCRSRQZV4JRZV3SXQXQXCTRDSCJJVQGPSPK7CMTQYQSZVQFPSZX7ER9DSQSZQFSPYXQGMMNVAHQZQGPXQRSCQN0VYQSZQG870H7Z"
	testPluginRecipient = "age1se1qfgtdtgsk5htc2zjx228pz7vhemu8ruqfzmwtknpt8k9tj9k4x4wges28jh"
)

// mockCryptoService wraps a real crypto service and counts decrypt calls
type mockCryptoService struct {
	domain.CryptoService
	mu           sync.Mutex
	decryptCalls int
}

func newMockCryptoService(underlying domain.CryptoService) *mockCryptoService {
	return &mockCryptoService{
		CryptoService: underlying,
	}
}

func (m *mockCryptoService) DecryptPrivateKey(pemData []byte) (crypto.Signer, error) {
	m.mu.Lock()
	m.decryptCalls++
	callCount := m.decryptCalls
	m.mu.Unlock()

	// Log each decrypt call for visibility
	t := testing.TB(nil) // We'll pass this from test context
	if t != nil {
		t.Logf("DecryptPrivateKey called (call #%d) - would require authentication", callCount)
	}

	return m.CryptoService.DecryptPrivateKey(pemData)
}

func (m *mockCryptoService) GetDecryptCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.decryptCalls
}

func (m *mockCryptoService) ResetCallCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decryptCalls = 0
}

func TestCryptoService_KeyCaching(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "plugin_identity.txt")

	if err := os.WriteFile(identityPath, []byte(testPluginIdentity), 0600); err != nil {
		t.Fatalf("Failed to create test identity file: %v", err)
	}

	config := domain.PluginConfig{
		IdentityFile: identityPath,
		Recipients:   []string{testPluginRecipient},
	}

	provider := identity.NewPluginProvider(config)

	// Create mock crypto service to count decrypt calls
	mockSvc := newMockCryptoService(cryptoSvc.NewAgeService(provider))

	// Test the new caching crypto service wrapping the mock
	cachedSvc := cryptoSvc.NewCachedCryptoService(mockSvc)

	// Generate a test key to encrypt/decrypt
	baseService := cryptoSvc.NewService()
	testKey, err := baseService.GeneratePrivateKey(domain.RSA2048)
	if err != nil {
		t.Fatalf("Could not generate test key: %v", err)
	}

	// Encrypt the key
	encryptedKey, err := cachedSvc.EncryptPrivateKey(testKey)
	if err != nil {
		t.Skipf("Could not encrypt test key (plugin not available): %v", err)
	}

	t.Log("Testing key caching - simulating the ca host issue scenario...")
	t.Log("This simulates: ResolveHostConfig + LoadCAKey + IssueHost decryptions")

	// Verify no decrypt calls yet
	if mockSvc.GetDecryptCallCount() != 0 {
		t.Errorf("Expected 0 decrypt calls initially, got %d", mockSvc.GetDecryptCallCount())
	}

	// First decryption (simulates ResolveHostConfig validation)
	key1, err1 := cachedSvc.DecryptPrivateKey(encryptedKey)
	if err1 != nil {
		t.Skipf("First decryption failed (plugin not available): %v", err1)
	}
	t.Log("First decryption completed (would require hardware authentication)")

	// Verify first call was made
	if mockSvc.GetDecryptCallCount() != 1 {
		t.Errorf("Expected 1 decrypt call after first decryption, got %d", mockSvc.GetDecryptCallCount())
	}

	// Second decryption (simulates LoadCAKey)
	key2, err2 := cachedSvc.DecryptPrivateKey(encryptedKey)
	if err2 != nil {
		t.Errorf("Second decryption failed: %v", err2)
	}
	t.Log("Second decryption completed (should use cache - no hardware authentication)")

	// Verify still only 1 call (cache hit)
	if mockSvc.GetDecryptCallCount() != 1 {
		t.Errorf("Expected still 1 decrypt call after cache hit, got %d", mockSvc.GetDecryptCallCount())
	}

	// Third decryption (simulates IssueHost key loading)
	key3, err3 := cachedSvc.DecryptPrivateKey(encryptedKey)
	if err3 != nil {
		t.Errorf("Third decryption failed: %v", err3)
	}
	t.Log("Third decryption completed (should use cache - no hardware authentication)")

	// Verify still only 1 call (cache hit again)
	if mockSvc.GetDecryptCallCount() != 1 {
		t.Errorf("Expected still 1 decrypt call after second cache hit, got %d", mockSvc.GetDecryptCallCount())
	}

	// All keys should be the same cached instance
	if key1 != key2 || key2 != key3 {
		t.Error("Expected all decrypted keys to be the same cached instance")
		return
	}

	// Test cache clearing functionality
	cachedSvc.ClearKeyCache()
	t.Log("Cache cleared for testing purposes")

	// After cache clear, should require fresh decryption
	key4, err4 := cachedSvc.DecryptPrivateKey(encryptedKey)
	if err4 != nil {
		t.Errorf("Decryption after cache clear failed: %v", err4)
	}

	// Verify another decrypt call was made after cache clear
	if mockSvc.GetDecryptCallCount() != 2 {
		t.Errorf("Expected 2 decrypt calls after cache clear, got %d", mockSvc.GetDecryptCallCount())
	}

	// New key should be different instance (but functionally equivalent)
	if key1 == key4 {
		t.Error("Expected new key instance after cache clear")
	} else {
		t.Log("Cache clearing verified - new decrypt call made after cache clear")
	}

	t.Log("Key caching test completed successfully!")
}
