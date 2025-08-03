package crypto

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"filippo.io/age"

	"reactor.de/reactor-ca/internal/domain"
)

// AgeService implements the domain.CryptoService interface using age encryption.
type AgeService struct {
	*Service         // Embed original service for certificate operations
	identityProvider domain.IdentityProvider
}

// NewAgeService creates a new age-based crypto service.
func NewAgeService(identityProvider domain.IdentityProvider, clock domain.Clock) *AgeService {
	return &AgeService{
		Service:          NewService(clock),
		identityProvider: identityProvider,
	}
}

// EncryptPrivateKey encrypts a private key using age encryption.
func (s *AgeService) EncryptPrivateKey(key crypto.Signer) ([]byte, error) {
	recipients, err := s.identityProvider.GetRecipients()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipients: %w", err)
	}

	// Convert key to PEM
	keyPEM, err := s.privateKeyToPEM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode key to PEM: %w", err)
	}

	// Encrypt with age
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age encryptor: %w", err)
	}

	if _, err := w.Write(keyPEM); err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to write key data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptPrivateKey decrypts an age-encrypted private key.
func (s *AgeService) DecryptPrivateKey(data []byte) (crypto.Signer, error) {
	identity, err := s.identityProvider.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		// Map age decryption errors to domain errors for better UX
		if err.Error() == "no identity matched any of the recipients" {
			return nil, domain.ErrIncorrectPassword
		}
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	keyPEM, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted key: %w", err)
	}

	return s.pemToPrivateKey(keyPEM)
}

// privateKeyToPEM converts a private key to PEM format.
func (s *AgeService) privateKeyToPEM(key crypto.Signer) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

// pemToPrivateKey converts PEM data to a private key.
func (s *AgeService) pemToPrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback for older PKCS#1 RSA keys
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		// Fallback for older EC keys
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a crypto.Signer")
	}

	return signer, nil
}
