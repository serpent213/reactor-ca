package crypto

import (
	"crypto"
	"sync"

	"reactor.de/reactor-ca/internal/domain"
)

// CachedCryptoService wraps another CryptoService and caches decrypted private keys
// to avoid repeated hardware authentication for plugin-based identity providers.
type CachedCryptoService struct {
	domain.CryptoService

	mu       sync.RWMutex
	keyCache map[string]crypto.Signer // Cache decrypted keys by hash of encrypted data
}

// NewCachedCryptoService creates a new cached crypto service wrapping the provided service.
func NewCachedCryptoService(underlying domain.CryptoService) *CachedCryptoService {
	return &CachedCryptoService{
		CryptoService: underlying,
		keyCache:      make(map[string]crypto.Signer),
	}
}

// DecryptPrivateKey decrypts a private key, using cache to avoid repeated authentication.
func (c *CachedCryptoService) DecryptPrivateKey(pemData []byte) (crypto.Signer, error) {
	// Create cache key from encrypted data hash
	cacheKey := c.getCacheKey(pemData)

	// Check cache first
	c.mu.RLock()
	if cachedKey, exists := c.keyCache[cacheKey]; exists {
		c.mu.RUnlock()
		return cachedKey, nil
	}
	c.mu.RUnlock()

	// Cache miss - decrypt using underlying service
	key, err := c.CryptoService.DecryptPrivateKey(pemData)
	if err != nil {
		return nil, err
	}

	// Cache the decrypted key
	c.mu.Lock()
	c.keyCache[cacheKey] = key
	c.mu.Unlock()

	return key, nil
}

// ClearKeyCache clears all cached decrypted keys, forcing re-authentication on next decrypt.
func (c *CachedCryptoService) ClearKeyCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear the cache by creating new map
	c.keyCache = make(map[string]crypto.Signer)
}

// getCacheKey creates a deterministic cache key from encrypted data.
// Uses SHA-256 hash of the encrypted PEM data for consistent cache keys.
func (c *CachedCryptoService) getCacheKey(pemData []byte) string {
	hash := crypto.SHA256.New()
	hash.Write(pemData)
	return string(hash.Sum(nil))
}
