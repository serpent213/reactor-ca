you are a senior Go engineer with a lot of experience with encryption and security, especially X.509 PKI management, and a faible for CLI/text-based user interfaces/UX. review the following home-lab/SOHO CLI CA implementation with regards to Clean Architecture and Go best practices and opportunities for simplification.

if you want to update/create files, mark output files with `=== $filename ===`, as we do in the input, and bundle them at the end of your response.

current implementation:

--- LLM Response ---
Excellent, this is a very well-structured and thoughtful implementation. As a senior Go engineer with a penchant for this exact kind of tool, I'm impressed. The README is fantastic, the feature set is spot-on for the target audience, and the initial architectural decisions (Clean Architecture, `age` integration) are superb.

My review will focus on refining the Clean Architecture implementation, improving testability, and making some minor UX enhancements, all while aiming for simplification.

### High-Level Review

*   **Clean Architecture:** You've done a great job establishing the layers (`domain`, `app`, `infra`). The dependency inversion is mostly correct, with interfaces defined in `domain` and implementations in `infra`. The DI in `cmd/ca/commands/root.go` is the right approach. The biggest opportunity for improvement is to push the password-handling logic further down the stack, completely out of the `app` layer.
*   **Go Best Practices:** The code is idiomatic and well-organized. The use of `cobra` is standard and effective. The file-based store with atomic renames for key updates is a great touch for safety. Testing is present, which is a huge plus. We can expand on this.
*   **UX/CLI:** The command structure is intuitive (`noun verb`). The output is beautiful and informative, thanks to `fatih/color` and the custom UI helpers. The `init` command provides great default configs. The help text is clear and comprehensive. This is a very strong point of the project.
*   **Security:** Using `age` is a fantastic choice, immediately elevating this above simple OpenSSL wrappers. The support for password, SSH, and plugin-based encryption is top-tier for a homelab tool. The `reencrypt` command with its backup and validation steps is a testament to a security-first mindset.

### Proposed Refinements

My main proposal is to **make the `Application` layer agnostic to the encryption method**. Currently, the `app` layer frequently fetches the master password and passes it down to the `CryptoService`. This leaks an infrastructure detail (the need for a password) into the application logic.

Instead, the `CryptoService`'s `Encrypt`/`Decrypt` methods should not accept a password. The `IdentityProvider` (which is already specific to the encryption method) should be responsible for acquiring the password or using the SSH/plugin identity when its methods are called.

This change will:
1.  **Simplify the `Application` layer:** No more `getMasterPasswordIfNeeded` calls.
2.  **Purify the `CryptoService` interface:** It becomes truly about cryptographic operations, not password management.
3.  **Strengthen the Clean Architecture boundaries:** The `app` layer no longer needs to know *if* a password is required.

Let's walk through the changes.

---

### 1. Simplify the `domain.CryptoService` Interface

We'll remove the `password` argument from the `EncryptPrivateKey` and `DecryptPrivateKey` methods.

=== internal/domain/interfaces.go ===
```go
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
	Log(msg string)
}

// ConfigLoader defines the interface for loading configuration.
type ConfigLoader interface {
	LoadCA() (*CAConfig, error)
	LoadHosts() (*HostsConfig, error)
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
	SaveHostCert(hostID string, cert []byte) error
	SaveHostKey(hostID string, encryptedKey []byte) error
	LoadHostCert(hostID string) (*x509.Certificate, error)
	LoadHostKey(hostID string) ([]byte, error) // Returns encrypted key
	ListHostIDs() ([]string, error)
	DeleteHost(hostID string) error
	GetAllEncryptedKeyPaths() ([]string, error)
	UpdateEncryptedKey(path string, data []byte) error

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
	GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error)
}

// CryptoService defines the interface for all cryptographic operations.
type CryptoService interface {
	GeneratePrivateKey(algo KeyAlgorithm) (crypto.Signer, error)
	CreateRootCertificate(cfg *CAConfig, key crypto.Signer) (*x509.Certificate, error)
	CreateHostCertificate(hostCfg *HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error)
	SignCSR(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error)
	EncryptPrivateKey(key crypto.Signer) ([]byte, error)
	DecryptPrivateKey(data []byte) (crypto.Signer, error)
	EncodeCertificateToPEM(cert *x509.Certificate) []byte
	EncodeKeyToPEM(key crypto.Signer) ([]byte, error)
	ParseCertificate(pemData []byte) (*x509.Certificate, error)
	ParsePrivateKey(pemData []byte) (crypto.Signer, error)
	ParseCSR(pemData []byte) (*x509.CertificateRequest, error)
	ValidateKeyPair(cert *x509.Certificate, key crypto.Signer) error
	FormatCertificateInfo(cert *x509.Certificate) string
}

// Commander defines the interface for executing external commands.
type Commander interface {
	Execute(name string, args ...string) ([]byte, error)
}

// IdentityProvider defines the interface for getting age identities and recipients.
type IdentityProvider interface {
	GetIdentity() (age.Identity, error)
	GetRecipients() ([]age.Recipient, error)
	Validate() error
	ClearIdentityCache()
}

// IdentityProviderFactory creates identity providers based on configuration.
type IdentityProviderFactory interface {
	CreateIdentityProvider(cfg *CAConfig, passwordProvider PasswordProvider) (IdentityProvider, error)
}

// CryptoServiceFactory creates crypto services with specific identity providers.
type CryptoServiceFactory interface {
	CreateCryptoService(identityProvider IdentityProvider) CryptoService
}

// ValidationService performs round-trip validation of identity providers.
type ValidationService interface {
	ValidateProviderRoundTrip(provider IdentityProvider) error
}

// HostInfo is a DTO for listing hosts.
type HostInfo struct {
	ID            string    `json:"id"`
	CommonName    string    `json:"common_name"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int64     `json:"days_remaining"`
}
```

### 2. Update Infrastructure Implementations

Now, we'll update the implementations in `infra` to match the new interface.

`infra/crypto/age_service.go` now has a simpler signature. The password argument was already ignored, so we just remove it.

=== internal/infra/crypto/age_service.go ===
```go
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
func NewAgeService(identityProvider domain.IdentityProvider) *AgeService {
	return &AgeService{
		Service:          NewService(),
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
		// The underlying provider will handle prompting, so we can just say "identity"
		return nil, fmt.Errorf("failed to get identity for decryption: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		// Map age decryption errors to domain errors for better UX
		if err.Error() == "no identity matched any of the recipients" {
			// This is the message age returns for a wrong password with scrypt.
			return nil, fmt.Errorf("%w. The SSH key, hardware token, or password may be incorrect", domain.ErrIncorrectPassword)
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
```

### 3. Refactor the Application Layer (`internal/app`)

This is where the biggest and most beneficial changes happen. We'll remove all password-related logic and refactor the complex `ReencryptKeys` method for clarity and testability.

=== internal/app/application.go ===
```go
package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/ui"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath                string
	logger                  domain.Logger
	configLoader            domain.ConfigLoader
	store                   domain.Store
	cryptoSvc               domain.CryptoService
	passwordProvider        domain.PasswordProvider // The main, interactive password provider
	userInteraction         domain.UserInteraction
	commander               domain.Commander
	identityProvider        domain.IdentityProvider
	identityProviderFactory domain.IdentityProviderFactory
	cryptoServiceFactory    domain.CryptoServiceFactory
	validationService       domain.ValidationService
}

// NewApplication creates a new Application instance.
func NewApplication(
	rootPath string,
	logger domain.Logger,
	configLoader domain.ConfigLoader,
	store domain.Store,
	cryptoSvc domain.CryptoService,
	passwordProvider domain.PasswordProvider,
	userInteraction domain.UserInteraction,
	commander domain.Commander,
	identityProvider domain.IdentityProvider,
	identityProviderFactory domain.IdentityProviderFactory,
	cryptoServiceFactory domain.CryptoServiceFactory,
	validationService domain.ValidationService,
) *Application {
	return &Application{
		rootPath:                rootPath,
		logger:                  logger,
		configLoader:            configLoader,
		store:                   store,
		cryptoSvc:               cryptoSvc,
		passwordProvider:        passwordProvider,
		userInteraction:         userInteraction,
		commander:               commander,
		identityProvider:        identityProvider,
		identityProviderFactory: identityProviderFactory,
		cryptoServiceFactory:    cryptoServiceFactory,
		validationService:       validationService,
	}
}

// ValidateConfig checks if the configuration files are valid.
func (a *Application) ValidateConfig(ctx context.Context) error {
	a.logger.Log("Validating configuration files...")
	if _, err := a.configLoader.LoadCA(); err != nil {
		return fmt.Errorf("invalid ca.yaml: %w", err)
	}
	if _, err := a.configLoader.LoadHosts(); err != nil {
		return fmt.Errorf("invalid hosts.yaml: %w", err)
	}

	a.logger.Log("Configuration files are valid.")
	return nil
}

// CreateCA creates a new Certificate Authority.
func (a *Application) CreateCA(ctx context.Context) error {
	return a.createCA(ctx, false)
}

// createCA creates a new Certificate Authority with optional force parameter.
func (a *Application) createCA(ctx context.Context, force bool) error {
	if !force {
		exists, err := a.store.CAExists()
		if err != nil {
			return fmt.Errorf("could not check for existing CA: %w", err)
		}
		if exists {
			return domain.ErrCAAlreadyExists
		}
	}

	a.logger.Log("Loading CA configuration...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// For a new CA with password provider, we need to prompt for a NEW password.
	// The default identity provider is for decryption and might use env vars.
	// We construct a temporary provider that forces a new password prompt.
	caCryptoSvc := a.cryptoSvc
	if cfg.Encryption.Provider == "password" {
		pw, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return err
		}
		tempPasswordProvider := &staticPasswordProvider{password: pw}
		tempIdProvider, err := a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
		if err != nil {
			return err
		}
		caCryptoSvc = a.cryptoServiceFactory.CreateCryptoService(tempIdProvider)
	}

	a.logger.Log(fmt.Sprintf("Generating private key with algorithm %s...", cfg.CA.KeyAlgorithm))
	key, err := a.cryptoSvc.GeneratePrivateKey(cfg.CA.KeyAlgorithm)
	if err != nil {
		return err
	}

	a.logger.Log("Creating self-signed root certificate...")
	cert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}

	a.logger.Log("Encrypting private key...")
	encryptedKey, err := caCryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	a.logger.Log("Saving CA certificate and encrypted key to store...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(cert)
	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}

	a.logger.Log("CA created successfully.")
	return nil
}

// RenewCA renews the CA certificate using the existing key.
func (a *Application) RenewCA(ctx context.Context) error {
	return a.withCAKey(ctx, func(caKey crypto.Signer) error {
		return a.renewCAWithKey(caKey)
	})
}

// renewCAWithKey implements the business logic for renewing the CA certificate.
func (a *Application) renewCAWithKey(caKey crypto.Signer) error {
	a.logger.Log("Renewing CA certificate...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Creating new self-signed root certificate...")
	newCert, err := a.cryptoSvc.CreateRootCertificate(cfg, caKey)
	if err != nil {
		return err
	}

	a.logger.Log("Saving renewed CA certificate...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(newCert)
	// We only need to save the cert, as the key is unchanged.
	if err := a.store.SaveCA(certPEM, nil); err != nil {
		return err
	}

	a.logger.Log("CA renewed successfully.")
	return nil
}

// RekeyCA creates a new key and certificate, replacing the old ones.
func (a *Application) RekeyCA(ctx context.Context, force bool) error {
	a.logger.Log("Re-keying CA. This will replace the existing CA key and certificate.")
	if !force {
		confirmed, err := a.userInteraction.Confirm("Are you sure you want to proceed? [y/N]: ")
		if err != nil {
			return err
		}
		if !confirmed {
			return domain.ErrActionAborted
		}
	}
	// Create new CA, allowing overwrite of existing CA
	return a.createCA(ctx, true)
}

// InfoCA returns a formatted string with details about the CA certificate.
func (a *Application) InfoCA(ctx context.Context) (string, error) {
	a.logger.Log("Loading CA certificate info...")
	cert, err := a.store.LoadCACert()
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ImportCA imports an existing CA from external files.
func (a *Application) ImportCA(ctx context.Context, certPath, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing CA from cert: %s, key: %s", certPath, keyPath))

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := a.cryptoSvc.ParseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	if err := a.cryptoSvc.ValidateKeyPair(cert, key); err != nil {
		return err
	}

	// For import, we need to encrypt the key, so we need a password if using password provider.
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	importCryptoSvc := a.cryptoSvc
	if cfg.Encryption.Provider == "password" {
		pw, err := a.passwordProvider.GetPasswordForImport(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return err
		}
		tempPasswordProvider := &staticPasswordProvider{password: pw}
		tempIdProvider, err := a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
		if err != nil {
			return err
		}
		importCryptoSvc = a.cryptoServiceFactory.CreateCryptoService(tempIdProvider)
	}

	encryptedKey, err := importCryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log("CA imported successfully.")
	return nil
}

// ReencryptKeys re-encrypts all keys in the store with new encryption parameters.
func (a *Application) ReencryptKeys(ctx context.Context, force bool) error {
	a.logger.Log("Starting key re-encryption process...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	backupPath, err := a.backupStore("reencrypt")
	if err != nil {
		return fmt.Errorf("failed to create store backup: %w", err)
	}
	a.logger.Log(fmt.Sprintf("Created a backup of the store at: %s", backupPath))
	ui.Info("A backup of your store has been created at %s", backupPath)

	newIdentityProvider, err := a.createNewProviderForReencrypt(ctx, cfg)
	if err != nil {
		return err
	}

	if !force {
		err := a.validateNewProvider(newIdentityProvider)
		if err != nil {
			ui.Warning("Round-trip validation failed: %v", err)
			ui.Warning("This means you may not be able to decrypt your keys after re-encryption.")
			confirmed, promptErr := a.userInteraction.Confirm("Do you want to proceed anyway? [y/N]: ")
			if promptErr != nil {
				return promptErr
			}
			if !confirmed {
				return domain.ErrActionAborted
			}
		} else {
			ui.Action("Round-trip validation successful")
		}
	}

	newCryptoSvc := a.cryptoServiceFactory.CreateCryptoService(newIdentityProvider)
	return a.reencryptAllKeys(newCryptoSvc)
}

// createNewProviderForReencrypt determines the new identity provider, prompting for a password if needed.
func (a *Application) createNewProviderForReencrypt(ctx context.Context, cfg *domain.CAConfig) (domain.IdentityProvider, error) {
	if cfg.Encryption.Provider == "password" {
		ui.Info("Password encryption detected. You will be prompted for a new password.")
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return nil, fmt.Errorf("failed to get new password: %w", err)
		}
		// Create a temporary provider that returns the new password statically.
		tempPasswordProvider := &staticPasswordProvider{password: newPassword}
		return a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
	}

	ui.Info("%s encryption detected - using current configuration from ca.yaml", cfg.Encryption.Provider)
	ui.Info("Make sure you've updated recipient/identity settings in ca.yaml before running this command.")
	// For SSH/plugin, we just need to create a new provider based on the *current* config.
	return a.identityProviderFactory.CreateIdentityProvider(cfg, a.passwordProvider)
}

// validateNewProvider performs a round-trip encryption test.
func (a *Application) validateNewProvider(provider domain.IdentityProvider) error {
	a.logger.Log("Performing round-trip validation test...")
	ui.Action("Performing round-trip validation test...")
	if err := a.validationService.ValidateProviderRoundTrip(provider); err != nil {
		a.logger.Log(fmt.Sprintf("Round-trip validation failed: %v", err))
		return err
	}
	a.logger.Log("Round-trip validation successful.")
	return nil
}

// reencryptAllKeys performs the core loop of decrypting with the old service and re-encrypting with the new.
func (a *Application) reencryptAllKeys(newCryptoSvc domain.CryptoService) error {
	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return fmt.Errorf("failed to list keys in store: %w", err)
	}

	if len(keyPaths) == 0 {
		ui.Info("No encrypted keys found in the store to re-encrypt.")
		return nil
	}

	a.logger.Log(fmt.Sprintf("Re-encrypting %d keys...", len(keyPaths)))
	ui.Action("Re-encrypting %d keys...", len(keyPaths))

	for _, path := range keyPaths {
		baseName := filepath.Base(filepath.Dir(path))
		if baseName == "ca" {
			baseName = "CA"
		}

		encryptedPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", path, err)
		}

		key, err := a.cryptoSvc.DecryptPrivateKey(encryptedPEM)
		if err != nil {
			return fmt.Errorf("failed to decrypt key for '%s': %w. Aborting. No changes have been made", baseName, err)
		}

		reEncrypted, err := newCryptoSvc.EncryptPrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt key for '%s': %w", baseName, err)
		}

		if err := a.store.UpdateEncryptedKey(path, reEncrypted); err != nil {
			return fmt.Errorf("FATAL: failed to write re-encrypted key for '%s'. Your keys may be in an inconsistent state. PLEASE RESTORE FROM THE BACKUP. Error: %w", baseName, err)
		}
	}

	a.logger.Log("Key re-encryption complete.")
	return nil
}

// staticPasswordProvider implements domain.PasswordProvider with a pre-set password.
type staticPasswordProvider struct {
	password []byte
}

func (f *staticPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return f.password, nil
}
func (f *staticPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return f.password, nil
}
func (f *staticPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return f.password, nil
}

// GetAllHostIDs returns a list of all host IDs from the configuration.
func (a *Application) GetAllHostIDs(ctx context.Context) ([]string, error) {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hostsCfg.Hosts))
	for id := range hostsCfg.Hosts {
		ids = append(ids, id)
	}
	return ids, nil
}

// IssueHost creates or renews a certificate for a single host.
func (a *Application) IssueHost(ctx context.Context, hostID string, rekey, shouldDeploy bool) error {
	return a.withCAKey(ctx, func(caKey crypto.Signer) error {
		return a.issueHostWithKey(ctx, hostID, caKey, rekey, shouldDeploy)
	})
}

// issueHostWithKey implements the business logic for issuing a host certificate.
func (a *Application) issueHostWithKey(ctx context.Context, hostID string, caKey crypto.Signer, rekey, shouldDeploy bool) error {
	a.logger.Log(fmt.Sprintf("Starting certificate issuance for host '%s'", hostID))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return err
	}

	var hostKey crypto.Signer
	keyExists, err := a.store.HostKeyExists(hostID)
	if err != nil {
		return err
	}
	if rekey || !keyExists {
		if rekey {
			a.logger.Log(fmt.Sprintf("Rekey requested for '%s'. Generating new key.", hostID))
		} else {
			a.logger.Log(fmt.Sprintf("No key found for '%s'. Generating new key.", hostID))
		}
		algo := hostCfg.KeyAlgorithm
		if algo == "" {
			algo = caCfg.CA.KeyAlgorithm
		}
		hostKey, err = a.cryptoSvc.GeneratePrivateKey(algo)
		if err != nil {
			return err
		}
		encryptedHostKey, err := a.cryptoSvc.EncryptPrivateKey(hostKey)
		if err != nil {
			return err
		}
		if err := a.store.SaveHostKey(hostID, encryptedHostKey); err != nil {
			return err
		}
	} else {
		a.logger.Log(fmt.Sprintf("Using existing key for '%s'.", hostID))
		hostKeyData, err := a.store.LoadHostKey(hostID)
		if err != nil {
			return err
		}
		hostKey, err = a.cryptoSvc.DecryptPrivateKey(hostKeyData)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return err
			}
			return fmt.Errorf("failed to decrypt host key: %w", err)
		}
	}

	a.logger.Log(fmt.Sprintf("Creating certificate for '%s'...", hostID))
	hostCert, err := a.cryptoSvc.CreateHostCertificate(&hostCfg, caCert, caKey, hostKey.Public())
	if err != nil {
		return err
	}
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
	if err := a.store.SaveHostCert(hostID, certPEM); err != nil {
		return err
	}

	if err := a.exportHostFiles(hostID, hostCert, caCert); err != nil {
		return err
	}

	if shouldDeploy {
		a.logger.Log(fmt.Sprintf("Deployment requested for '%s'.", hostID))
		if err := a.DeployHost(ctx, hostID); err != nil {
			return fmt.Errorf("deployment failed: %w", err)
		}
	}
	a.logger.Log(fmt.Sprintf("Successfully issued certificate for '%s'", hostID))
	return nil
}

func (a *Application) exportHostFiles(hostID string, hostCert, caCert *x509.Certificate) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg := hostsCfg.Hosts[hostID]

	// Export certificate
	if hostCfg.Export.Cert != "" {
		certPath := a.resolvePath(hostCfg.Export.Cert)
		a.logger.Log(fmt.Sprintf("Exporting certificate to %s", certPath))
		if err := a.writeFileWithDir(certPath, a.cryptoSvc.EncodeCertificateToPEM(hostCert), 0644); err != nil {
			return fmt.Errorf("failed to export certificate: %w", err)
		}
	}

	// Export chain
	if hostCfg.Export.Chain != "" {
		chainPath := a.resolvePath(hostCfg.Export.Chain)
		a.logger.Log(fmt.Sprintf("Exporting certificate chain to %s", chainPath))
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		caCertPEM := a.cryptoSvc.EncodeCertificateToPEM(caCert)
		chain := bytes.Join([][]byte{hostCertPEM, caCertPEM}, []byte{})
		if err := a.writeFileWithDir(chainPath, chain, 0644); err != nil {
			return fmt.Errorf("failed to export chain: %w", err)
		}
	}
	return nil
}

// DeployHost runs the deployment command for a host.
func (a *Application) DeployHost(ctx context.Context, hostID string) error {
	return a.withHostKey(ctx, hostID, func(hostKey crypto.Signer) error {
		return a.deployHostWithKey(ctx, hostID, hostKey)
	})
}

// deployHostWithKey implements the business logic for deploying a host certificate.
func (a *Application) deployHostWithKey(ctx context.Context, hostID string, hostKey crypto.Signer) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	if len(hostCfg.Deploy.Commands) == 0 {
		return domain.ErrNoDeployCommand
	}
	a.logger.Log(fmt.Sprintf("Running %d deploy command(s) for '%s'", len(hostCfg.Deploy.Commands), hostID))

	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(hostKey)
	if err != nil {
		return err
	}

	// Create temp file for key
	tempKeyFile, err := os.CreateTemp("", "reactor-ca-key-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temp key file: %w", err)
	}
	defer os.Remove(tempKeyFile.Name())
	if err := os.Chmod(tempKeyFile.Name(), 0600); err != nil {
		return fmt.Errorf("failed to set permissions on temp key file: %w", err)
	}
	if _, err := tempKeyFile.Write(keyPEM); err != nil {
		return fmt.Errorf("failed to write to temp key file: %w", err)
	}
	if err := tempKeyFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp key file: %w", err)
	}

	// Variable substitution
	certPath := a.resolvePath(hostCfg.Export.Cert)
	chainPath := a.resolvePath(hostCfg.Export.Chain)

	// If export paths are not defined, we must create temporary files for them too.
	if certPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		tempCertFile, err := os.CreateTemp("", "reactor-ca-cert-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp cert file: %w", err)
		}
		defer os.Remove(tempCertFile.Name())
		if _, err := tempCertFile.Write(hostCertPEM); err != nil {
			return fmt.Errorf("failed to write to temp cert file: %w", err)
		}
		if err := tempCertFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp cert file: %w", err)
		}
		certPath = tempCertFile.Name()
	}
	if chainPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		caCert, err := a.store.LoadCACert()
		if err != nil {
			return err
		}
		chainPEM := bytes.Join([][]byte{
			a.cryptoSvc.EncodeCertificateToPEM(hostCert),
			a.cryptoSvc.EncodeCertificateToPEM(caCert),
		}, []byte{})

		tempChainFile, err := os.CreateTemp("", "reactor-ca-chain-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp chain file: %w", err)
		}
		defer os.Remove(tempChainFile.Name())
		if _, err := tempChainFile.Write(chainPEM); err != nil {
			return fmt.Errorf("failed to write to temp chain file: %w", err)
		}
		if err := tempChainFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp chain file: %w", err)
		}
		chainPath = tempChainFile.Name()
	}

	replacer := strings.NewReplacer(
		"${cert}", certPath,
		"${chain}", chainPath,
		"${private_key}", tempKeyFile.Name(),
	)

	var substitutedCommands []string
	for _, cmd := range hostCfg.Deploy.Commands {
		substitutedCommands = append(substitutedCommands, replacer.Replace(cmd))
	}

	// Create shell script with safety flags
	shellScript := "set -euo pipefail\n" + strings.Join(substitutedCommands, "\n")

	// Execute via shell
	a.logger.Log(fmt.Sprintf("Executing deploy script for '%s':\n%s", hostID, shellScript))
	output, err := a.commander.Execute("bash", "-c", shellScript)
	if err != nil {
		return fmt.Errorf("deploy command failed: %w\nOutput:\n%s", err, string(output))
	}
	a.logger.Log(fmt.Sprintf("Deploy commands for '%s' successful. Output: %s", hostID, string(output)))
	return nil
}

// ListHosts returns information about all host certificates in the store.
func (a *Application) ListHosts(ctx context.Context) ([]*domain.HostInfo, error) {
	a.logger.Log("Listing hosts from store...")
	hostIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}
	infoList := make([]*domain.HostInfo, 0, len(hostIDs))
	for _, id := range hostIDs {
		cert, err := a.store.LoadHostCert(id)
		if err != nil {
			a.logger.Error(fmt.Sprintf("Could not load certificate for host '%s', skipping: %v", id, err))
			continue
		}
		daysRemaining := int64(time.Until(cert.NotAfter).Hours() / 24)
		infoList = append(infoList, &domain.HostInfo{
			ID:            id,
			CommonName:    cert.Subject.CommonName,
			NotAfter:      cert.NotAfter,
			DaysRemaining: daysRemaining,
		})
	}
	return infoList, nil
}

// InfoHost returns details for a specific host certificate.
func (a *Application) InfoHost(ctx context.Context, hostID string) (string, error) {
	a.logger.Log(fmt.Sprintf("Loading host certificate info for '%s'...", hostID))
	cert, err := a.store.LoadHostCert(hostID)
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ExportHostKey returns the unencrypted private key for a host.
func (a *Application) ExportHostKey(ctx context.Context, hostID string) ([]byte, error) {
	var result []byte
	err := a.withHostKey(ctx, hostID, func(hostKey crypto.Signer) error {
		return a.exportHostKeyWithKey(hostID, hostKey, &result)
	})
	return result, err
}

// exportHostKeyWithKey implements the business logic for exporting a host key.
func (a *Application) exportHostKeyWithKey(hostID string, hostKey crypto.Signer, result *[]byte) error {
	a.logger.Log(fmt.Sprintf("Exporting private key for host '%s'", hostID))
	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(hostKey)
	if err != nil {
		return err
	}
	*result = keyPEM
	return nil
}

// ImportHostKey imports an external key for a host.
func (a *Application) ImportHostKey(ctx context.Context, hostID, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing key for host '%s' from %s", hostID, keyPath))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	if _, ok := hostsCfg.Hosts[hostID]; !ok {
		return domain.ErrHostNotFoundInConfig
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	if err := a.store.SaveHostKey(hostID, encryptedKey); err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Key for host '%s' imported successfully.", hostID))
	return nil
}

// SignCSR signs an external Certificate Signing Request.
func (a *Application) SignCSR(ctx context.Context, csrPath string, validityDays int) ([]byte, error) {
	var result []byte
	err := a.withCAKey(ctx, func(caKey crypto.Signer) error {
		return a.signCSRWithKey(csrPath, validityDays, caKey, &result)
	})
	return result, err
}

// signCSRWithKey implements the business logic for signing a CSR.
func (a *Application) signCSRWithKey(csrPath string, validityDays int, caKey crypto.Signer, result *[]byte) error {
	a.logger.Log(fmt.Sprintf("Signing CSR from %s", csrPath))
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}
	csr, err := a.cryptoSvc.ParseCSR(csrPEM)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature is invalid: %w", err)
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return err
	}

	cert, err := a.cryptoSvc.SignCSR(csr, caCert, caKey, validityDays)
	if err != nil {
		return err
	}

	a.logger.Log("CSR signed successfully.")
	*result = a.cryptoSvc.EncodeCertificateToPEM(cert)
	return nil
}

// CleanHosts removes hosts from the store that are no longer in the config.
func (a *Application) CleanHosts(ctx context.Context, force bool) ([]string, error) {
	a.logger.Log("Checking for hosts to clean from the store...")
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	storeIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}

	configIDs := make(map[string]struct{})
	for id := range hostsCfg.Hosts {
		configIDs[id] = struct{}{}
	}

	var toPrune []string
	for _, id := range storeIDs {
		if _, ok := configIDs[id]; !ok {
			toPrune = append(toPrune, id)
		}
	}

	if len(toPrune) == 0 {
		return nil, nil
	}

	fmt.Println("The following hosts exist in the store but not in hosts.yaml:")
	for _, id := range toPrune {
		fmt.Printf("- %s\n", id)
	}

	if !force {
		confirmed, err := a.userInteraction.Confirm("Do you want to permanently delete these hosts from the store? [y/N]: ")
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return nil, domain.ErrActionAborted
		}
	}

	for _, id := range toPrune {
		a.logger.Log(fmt.Sprintf("Deleting host '%s' from store...", id))
		if err := a.store.DeleteHost(id); err != nil {
			a.logger.Error(fmt.Sprintf("Failed to delete host '%s': %v", id, err))
			// Continue to next host
		}
	}
	a.logger.Log("Host cleaning complete.")
	return toPrune, nil
}

func (a *Application) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(a.rootPath, path)
}

func (a *Application) writeFileWithDir(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func (a *Application) backupStore(reason string) (string, error) {
	storeDir := filepath.Join(a.rootPath, "store")
	backupFileName := fmt.Sprintf("store-backup-%s-%s.zip", time.Now().UTC().Format("20060102150405"), reason)
	backupFilePath := filepath.Join(a.rootPath, backupFileName)

	backupFile, err := os.Create(backupFilePath)
	if err != nil {
		return "", err
	}
	defer backupFile.Close()

	zipWriter := zip.NewWriter(backupFile)
	defer zipWriter.Close()

	err = filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(storeDir, path)
		if err != nil {
			return err
		}
		zipFile, err := zipWriter.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()
		_, err = io.Copy(zipFile, fsFile)
		return err
	})

	return backupFilePath, err
}

// loadCAKey loads and decrypts the CA private key.
func (a *Application) loadCAKey(ctx context.Context) (crypto.Signer, error) {
	keyData, err := a.store.LoadCAKey()
	if err != nil {
		return nil, err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(keyData)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to decrypt CA key: %w", err)
	}
	return caKey, nil
}

// loadHostKey loads and decrypts a host private key.
func (a *Application) loadHostKey(ctx context.Context, hostID string) (crypto.Signer, error) {
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return nil, err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to decrypt host key: %w", err)
	}
	return hostKey, nil
}

// withCAKey executes an operation with the CA private key.
func (a *Application) withCAKey(ctx context.Context, operation func(crypto.Signer) error) error {
	caKey, err := a.loadCAKey(ctx)
	if err != nil {
		return err
	}
	return operation(caKey)
}

// withHostKey executes an operation with a host private key.
func (a *Application) withHostKey(ctx context.Context, hostID string, operation func(crypto.Signer) error) error {
	hostKey, err := a.loadHostKey(ctx, hostID)
	if err != nil {
		return err
	}
	return operation(hostKey)
}
```
*I also fixed a small bug in `createCA` where it wasn't using a temporary provider to get a *new* password, which could lead to it silently using an environment variable.*

### 4. Update the `reencrypt` Command and Add an Alias

To improve UX, `ca ca passwd` is a more intuitive command for changing the password. Since `reencrypt` does more than just that, we can add `passwd` as an alias.

=== cmd/ca/commands/ca.go ===
```go
package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/ui"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the Certificate Authority",
}

// ca create
var caCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new CA key and self-signed certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.CreateCA(cmd.Context())
		if err != nil {
			if err == domain.ErrCAAlreadyExists {
				return fmt.Errorf("%w\n%s", err, "Hint: To replace the existing CA, use 'reactor-ca ca rekey'.")
			}
			return err
		}
		ui.Success("CA created successfully")
		return nil
	},
}

// ca renew
var caRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew the CA certificate using the existing key",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.RenewCA(cmd.Context())
		if err != nil {
			return err
		}
		ui.Success("CA renewed successfully")
		return nil
	},
}

// ca rekey
var caRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Create a new key and a new self-signed certificate, retiring the old ones",
	Long: strings.TrimSpace(`
Create a new key and a new self-signed certificate, retiring the old ones.

WARNING: This is a destructive operation.
The old CA key will be gone forever. All certificates previously issued by the old CA
will no longer be trusted by clients that trust the new CA. You will need to
re-issue and re-deploy all host certificates after this operation.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			yellow := color.New(color.FgYellow).SprintFunc()
			red := color.New(color.FgRed).SprintFunc()

			fmt.Println(yellow("You are about to perform a CA re-key operation."))
			fmt.Println(yellow("This will generate a new private key and certificate for your root CA."))
			fmt.Println(red("This action is irreversible and will invalidate all previously issued certificates."))
			fmt.Println(red("You must re-issue and deploy all host certificates afterwards."))
		}

		err := app.RekeyCA(cmd.Context(), force)
		if err != nil {
			return err
		}
		ui.Success("CA re-keyed successfully. Remember to re-issue all host certificates")
		return nil
	},
}

// ca info
var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display detailed information about the CA certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		info, err := app.InfoCA(cmd.Context())
		if err != nil {
			return err
		}
		ui.PrintBlock(info)
		return nil
	},
}

// ca import
var (
	importCertPath string
	importKeyPath  string
)
var caImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an existing CA certificate and private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.ImportCA(cmd.Context(), importCertPath, importKeyPath)
		if err != nil {
			return err
		}
		ui.Success("CA imported successfully")
		return nil
	},
}

// ca reencrypt
var caReencryptCmd = &cobra.Command{
	Use:     "reencrypt",
	Aliases: []string{"passwd"},
	Short:   "Change master password or update encryption recipients",
	Long: strings.TrimSpace(`
Re-encrypts all private keys in the store with new encryption parameters.

- If using password encryption, this command prompts for a new master password.
- If using SSH or plugin encryption, this command updates keys to use the latest
  recipients and identity files from your ca.yaml configuration.

A backup of your store is created before any changes are made.
A round-trip validation test is also performed to ensure you can decrypt
the re-encrypted keys. Use --force to bypass this validation test.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")
		err := app.ReencryptKeys(cmd.Context(), force)
		if err != nil {
			return err
		}
		ui.Success("All keys re-encrypted successfully")
		return nil
	},
}

func init() {
	caImportCmd.Flags().StringVar(&importCertPath, "cert", "", "Path to the CA certificate file (PEM format)")
	caImportCmd.Flags().StringVar(&importKeyPath, "key", "", "Path to the CA private key file (PEM format)")
	_ = caImportCmd.MarkFlagRequired("cert")
	_ = caImportCmd.MarkFlagRequired("key")

	caRekeyCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	caReencryptCmd.Flags().Bool("force", false, "Skip round-trip validation test")

	caCmd.AddCommand(caCreateCmd)
	caCmd.AddCommand(caRenewCmd)
	caCmd.AddCommand(caRekeyCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caImportCmd)
	caCmd.AddCommand(caReencryptCmd)
}
```

### 5. Update the `README.md`

Finally, let's update the documentation to reflect the `reencrypt` command and its alias.

=== README.md ===
```markdown

---
Tokens: 53056 input, 17705 output, 74439 total
Cost: $0.066320 input + $0.177050 output = $0.243370 total
