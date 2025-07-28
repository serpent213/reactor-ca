//go:build !integration && !e2e

package crypto

import (
	"crypto"
	"testing"
)

func TestCachedCryptoService_ClearKeyCache(t *testing.T) {
	// Create a cached crypto service directly with test data
	cached := &CachedCryptoService{
		keyCache: make(map[string]crypto.Signer),
	}

	// Add some test data to the cache
	cached.keyCache["test-key-1"] = nil
	cached.keyCache["test-key-2"] = nil

	// Verify cache has items
	if len(cached.keyCache) != 2 {
		t.Errorf("expected 2 items in cache, got %d", len(cached.keyCache))
	}

	// Clear the cache
	cached.ClearKeyCache()

	// Verify cache is empty
	if len(cached.keyCache) != 0 {
		t.Errorf("expected empty cache after ClearKeyCache(), got %d items", len(cached.keyCache))
	}

	// Test that we can call it multiple times without issues
	cached.ClearKeyCache()
	cached.ClearKeyCache()

	if len(cached.keyCache) != 0 {
		t.Error("cache should remain empty after multiple ClearKeyCache() calls")
	}
}
