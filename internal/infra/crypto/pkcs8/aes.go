package pkcs8

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"errors"
)

var (
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

func init() {
	RegisterCipher(oidAES256GCM, func() Cipher {
		return AES256GCM
	})
}

// aesGCM implements AES-GCM cipher for PKCS#8
type aesGCM struct {
	oid     asn1.ObjectIdentifier
	keySize int
}

func (c aesGCM) IVSize() int {
	// GCM standard nonce size is 12 bytes (96 bits)
	return 12
}

func (c aesGCM) KeySize() int {
	return c.keySize
}

func (c aesGCM) OID() asn1.ObjectIdentifier {
	return c.oid
}

func (c aesGCM) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// GCM appends the authentication tag to the ciphertext
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

func (c aesGCM) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// GCM verifies the authentication tag and returns plaintext
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		// Convert GCM auth failure to password error for compatibility
		return nil, errors.New("pkcs8: incorrect password")
	}
	return plaintext, nil
}

// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = aesGCM{
	keySize: 32,
	oid:     oidAES256GCM,
}
