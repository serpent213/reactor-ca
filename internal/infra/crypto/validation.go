package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"reactor.de/reactor-ca/internal/domain"
)

// ValidateProviderRoundTrip performs a test encrypt/decrypt to ensure the provider works.
func ValidateProviderRoundTrip(provider domain.IdentityProvider) error {
	// Generate a test ECDSA private key
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate test key: %w", err)
	}

	// Create temporary crypto service with new provider
	tempCryptoSvc := NewAgeService(provider)

	// Encrypt test key (age service doesn't use the password parameter)
	encrypted, err := tempCryptoSvc.EncryptPrivateKey(testKey, nil)
	if err != nil {
		return fmt.Errorf("test encryption failed: %w", err)
	}

	// Decrypt test key
	decrypted, err := tempCryptoSvc.DecryptPrivateKey(encrypted, nil)
	if err != nil {
		return fmt.Errorf("test decryption failed: %w", err)
	}

	// Compare keys by comparing their public key representations
	if !equalPrivateKeys(testKey, decrypted) {
		return fmt.Errorf("round-trip validation failed: keys don't match after encrypt/decrypt cycle")
	}

	return nil
}

// equalPrivateKeys compares two private keys by comparing their public key representations.
func equalPrivateKeys(a, b crypto.Signer) bool {
	aPub, err := x509.MarshalPKIXPublicKey(a.Public())
	if err != nil {
		return false
	}
	bPub, err := x509.MarshalPKIXPublicKey(b.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(aPub, bPub)
}
