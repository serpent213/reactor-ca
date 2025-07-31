package domain

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
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

// unmarshalCaseInsensitive is a generic helper for case-insensitive YAML unmarshaling
func unmarshalCaseInsensitive[T ~string](value *yaml.Node, target *T, validValues []T, typeName string) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return err
	}

	upperStr := strings.ToUpper(str)

	for _, valid := range validValues {
		if string(valid) == upperStr {
			*target = T(upperStr)
			return nil
		}
	}

	return fmt.Errorf("unsupported %s: %s", typeName, str)
}

// UnmarshalYAML implements yaml.Unmarshaler to handle case-insensitive key algorithm parsing.
func (k *KeyAlgorithm) UnmarshalYAML(value *yaml.Node) error {
	validKeyAlgorithms := []KeyAlgorithm{RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519}
	return unmarshalCaseInsensitive(value, k, validKeyAlgorithms, "key algorithm")
}

// HashAlgorithm represents a supported cryptographic hash algorithm.
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA256"
	SHA384 HashAlgorithm = "SHA384"
	SHA512 HashAlgorithm = "SHA512"
)

// UnmarshalYAML implements yaml.Unmarshaler to handle case-insensitive hash algorithm parsing.
func (h *HashAlgorithm) UnmarshalYAML(value *yaml.Node) error {
	validHashAlgorithms := []HashAlgorithm{SHA256, SHA384, SHA512}
	return unmarshalCaseInsensitive(value, h, validHashAlgorithms, "hash algorithm")
}

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
