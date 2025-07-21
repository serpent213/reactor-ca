package domain

import (
	"crypto"
	"crypto/x509"
)

// KeyAlgorithm represents a supported cryptographic key algorithm.
type KeyAlgorithm string

const (
	RSA2048 KeyAlgorithm = "RSA2048"
	RSA3072 KeyAlgorithm = "RSA3072"
	RSA4096 KeyAlgorithm = "RSA4096"
	ECP256  KeyAlgorithm = "ECP256"
	ECP384  KeyAlgorithm = "ECP384"
	ECP521  KeyAlgorithm = "ECP521"
	ED25519 KeyAlgorithm = "ED25519"
)

// HashAlgorithm represents a supported cryptographic hash algorithm.
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA256"
	SHA384 HashAlgorithm = "SHA384"
	SHA512 HashAlgorithm = "SHA512"
)

// ToCryptoHash converts a domain HashAlgorithm to a crypto.Hash.
func (h HashAlgorithm) ToCryptoHash() (crypto.Hash, error) {
	switch h {
	case SHA256:
		return crypto.SHA256, nil
	case SHA384:
		return crypto.SHA384, nil
	case SHA512:
		return crypto.SHA512, nil
	default:
		return 0, x509.ErrUnsupportedAlgorithm
	}
}
