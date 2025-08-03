package domain

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"filippo.io/age"
)

// Logger defines the logging interface.
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Warning(msg string, args ...interface{})
	Log(msg string)
}

// ConfigLoader defines the interface for loading configuration.
type ConfigLoader interface {
	LoadCA() (*CAConfig, error)
	LoadHosts() (*HostsConfig, error)
	ValidateCAConfig(data []byte) error
	ValidateHostsConfig(data []byte) error
}

// Store defines the interface for persistence operations.
type Store interface {
	// CA operations
	CAExists() (bool, error)
	SaveCA(cert, encryptedKey []byte) error
	LoadCACert() (*x509.Certificate, error)
	LoadCAKey() ([]byte, error) // Returns encrypted key

	// Host operations
	HostExists(hostID string) (bool, error)
	HostKeyExists(hostID string) (bool, error)
	HostCertExists(hostID string) (bool, error)
	ValidateAgeKeyFile(hostID string) bool
	SaveHostCert(hostID string, cert []byte) error
	SaveHostKey(hostID string, encryptedKey []byte) error
	LoadHostCert(hostID string) (*x509.Certificate, error)
	LoadHostKey(hostID string) ([]byte, error) // Returns encrypted key
	ListHostIDs() ([]string, error)
	DeleteHost(hostID string) error
	GetAllEncryptedKeyPaths() ([]string, error)
	UpdateEncryptedKey(path string, data []byte) error

	// Backup operations
	CreateBackupFile(originalPath string) error
	RestoreFromBackup(originalPath string) error
	RemoveBackupFile(originalPath string) error

	// Path getters
	GetHostCertPath(hostID string) string
	GetHostKeyPath(hostID string) string
	GetCACertPath() string
}

// UserInteraction defines the interface for all user prompting and confirmation.
type UserInteraction interface {
	Confirm(prompt string) (bool, error)
}

// PasswordProvider defines the interface for retrieving the master password.
type PasswordProvider interface {
	GetMasterPassword(ctx context.Context, cfg PasswordConfig) ([]byte, error)
	GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error)
}

// CryptoService defines the interface for all cryptographic operations.
type CryptoService interface {
	GeneratePrivateKey(algo KeyAlgorithm) (crypto.Signer, error)
	CreateRootCertificate(cfg *CAConfig, key crypto.Signer) (*x509.Certificate, error)
	CreateHostCertificate(hostCfg *HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error)
	SignCSR(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error)
	EncryptPrivateKey(key crypto.Signer) ([]byte, error)
	DecryptPrivateKey(pemData []byte) (crypto.Signer, error)
	EncodeCertificateToPEM(cert *x509.Certificate) []byte
	EncodeKeyToPEM(key crypto.Signer) ([]byte, error)
	ParseCertificate(pemData []byte) (*x509.Certificate, error)
	ParsePrivateKey(pemData []byte) (crypto.Signer, error)
	ParseCSR(pemData []byte) (*x509.CertificateRequest, error)
	ValidateKeyPair(cert *x509.Certificate, key crypto.Signer) error
}

// Commander defines the interface for executing external commands.
type Commander interface {
	ExecuteInteractive(name string, args ...string) error
}

// IdentityProvider defines the interface for getting age identities and recipients.
type IdentityProvider interface {
	GetIdentity() (age.Identity, error)
	GetRecipients() ([]age.Recipient, error)
	Validate() error
}

// IdentityProviderFactory creates identity providers based on configuration.
type IdentityProviderFactory interface {
	CreateIdentityProvider(cfg *CAConfig, passwordProvider PasswordProvider) (IdentityProvider, error)
	CreateHostIdentityProvider(cfg *CAConfig, hostCfg *HostConfig, passwordProvider PasswordProvider) (IdentityProvider, error)
}

// CryptoServiceFactory creates crypto services with specific identity providers.
type CryptoServiceFactory interface {
	CreateCryptoService(identityProvider IdentityProvider) CryptoService
}

// ValidationService performs round-trip validation of identity providers.
type ValidationService interface {
	ValidateProviderRoundTrip(provider IdentityProvider) error
}

// Clock defines the interface for time operations.
type Clock interface {
	Now() time.Time
}

// HostInfo is a DTO for listing hosts.
type HostInfo struct {
	ID            string     `json:"id"`
	CommonName    string     `json:"common_name"`
	NotAfter      time.Time  `json:"not_after"`
	DaysRemaining int64      `json:"days_remaining"`
	Status        HostStatus `json:"status"`
	KeyAlgorithm  string     `json:"key_algorithm"`
	KeyLength     int        `json:"key_length"`
	HashAlgorithm string     `json:"hash_algorithm"`
	// Status flags for cert/key availability and integrity
	CertMissing bool `json:"cert_missing,omitempty"`
	CertBroken  bool `json:"cert_broken,omitempty"`
	KeyMissing  bool `json:"key_missing,omitempty"`
	KeyBroken   bool `json:"key_broken,omitempty"`
}

// HostStatus represents the status of a host certificate
type HostStatus string

const (
	HostStatusIssued      HostStatus = "issued"       // Certificate exists in store and is configured
	HostStatusConfigured  HostStatus = "configured"   // Defined in config but no certificate in store
	HostStatusOrphaned    HostStatus = "orphaned"     // Certificate exists in store but not in config
	HostStatusCertMissing HostStatus = "cert_missing" // Private key exists but certificate missing
	HostStatusKeyMissing  HostStatus = "key_missing"  // Certificate exists but private key missing
)
