package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAES256GCMEncryptDecrypt(t *testing.T) {
	// Test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	tests := []struct {
		name string
		key  interface{}
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecKey},
	}

	password := []byte("test-password")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{
				Cipher: AES256GCM,
				KDFOpts: PBKDF2Opts{
					SaltSize:       16,
					IterationCount: 100000,
					HMACHash:       crypto.SHA256,
				},
			}

			// Encrypt the private key
			encryptedDER, err := MarshalPrivateKey(tt.key, password, opts)
			if err != nil {
				t.Fatalf("MarshalPrivateKey failed: %v", err)
			}

			// Decrypt the private key
			decryptedKey, err := ParsePKCS8PrivateKey(encryptedDER, password)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
			}

			// Compare keys based on type
			switch origKey := tt.key.(type) {
			case *rsa.PrivateKey:
				decKey, ok := decryptedKey.(*rsa.PrivateKey)
				if !ok {
					t.Fatal("Decrypted key is not RSA")
				}
				if origKey.N.Cmp(decKey.N) != 0 {
					t.Fatal("RSA keys don't match")
				}
			case *ecdsa.PrivateKey:
				decKey, ok := decryptedKey.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatal("Decrypted key is not ECDSA")
				}
				if origKey.X.Cmp(decKey.X) != 0 || origKey.Y.Cmp(decKey.Y) != 0 {
					t.Fatal("ECDSA keys don't match")
				}
			}
		})
	}
}

func TestWrongPassword(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")

	opts := &Opts{
		Cipher: AES256GCM,
		KDFOpts: PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       crypto.SHA256,
		},
	}

	// Encrypt with correct password
	encryptedDER, err := MarshalPrivateKey(rsaKey, password, opts)
	if err != nil {
		t.Fatalf("MarshalPrivateKey failed: %v", err)
	}

	// Try to decrypt with wrong password
	_, err = ParsePKCS8PrivateKey(encryptedDER, wrongPassword)
	if err == nil {
		t.Fatal("Expected error with wrong password")
	}
	if err.Error() != "pkcs8: incorrect password" {
		t.Fatalf("Expected 'pkcs8: incorrect password', got '%v'", err)
	}
}

func TestUnencryptedKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal without password
	der, err := MarshalPrivateKey(rsaKey, nil, nil)
	if err != nil {
		t.Fatalf("MarshalPrivateKey failed: %v", err)
	}

	// Parse without password
	decryptedKey, err := ParsePKCS8PrivateKey(der, nil)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}

	decKey, ok := decryptedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Decrypted key is not RSA")
	}
	if rsaKey.N.Cmp(decKey.N) != 0 {
		t.Fatal("RSA keys don't match")
	}
}
