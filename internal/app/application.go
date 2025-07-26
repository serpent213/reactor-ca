package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/ui"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath                string
	logger                  domain.Logger
	configLoader            domain.ConfigLoader
	store                   domain.Store
	cryptoSvc               domain.CryptoService
	passwordProvider        domain.PasswordProvider
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
	if _, err := a.configLoader.LoadCA(); err != nil {
		return err
	}
	if _, err := a.configLoader.LoadHosts(); err != nil {
		return err
	}

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

	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// For CA creation, we need to ask for password confirmation
	cryptoSvc := a.cryptoSvc
	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		// For password encryption, prompt for new password with confirmation
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return err
		}
		// Create temporary password provider and crypto service for CA creation
		tempPasswordProvider := &password.StaticPasswordProvider{Password: newPassword}
		tempIdentityProvider, err := a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
		if err != nil {
			return fmt.Errorf("failed to create identity provider for CA creation: %w", err)
		}
		cryptoSvc = a.cryptoServiceFactory.CreateCryptoService(tempIdentityProvider)
	}

	key, err := cryptoSvc.GeneratePrivateKey(cfg.CA.KeyAlgorithm)
	if err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Generated private key with algorithm %s", cfg.CA.KeyAlgorithm))

	cert, err := cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}
	a.logger.Log("Created self-signed root certificate")

	encryptedKey, err := cryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	certPEM := a.cryptoSvc.EncodeCertificateToPEM(cert)
	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log("Saved CA certificate and encrypted key to store")

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
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	newCert, err := a.cryptoSvc.CreateRootCertificate(cfg, caKey)
	if err != nil {
		return err
	}
	a.logger.Log("Created new self-signed root certificate")

	certPEM := a.cryptoSvc.EncodeCertificateToPEM(newCert)
	// We only need to save the cert, as the key is unchanged.
	if err := a.store.SaveCA(certPEM, nil); err != nil {
		return err
	}
	a.logger.Log("Saved renewed CA certificate")

	return nil
}

// RekeyCA creates a new key and certificate, replacing the old ones.
func (a *Application) RekeyCA(ctx context.Context, force bool) error {
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
	if err := a.createCA(ctx, true); err != nil {
		return err
	}
	a.logger.Log("Successfully re-keyed CA with new key and certificate")
	return nil
}

// InfoCA returns a formatted string with details about the CA certificate.
func (a *Application) InfoCA(ctx context.Context) (string, error) {
	cert, err := a.store.LoadCACert()
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ImportCA imports an existing CA from external files.
func (a *Application) ImportCA(ctx context.Context, certPath, keyPath string) error {

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

	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// For CA import, we need to ask for password confirmation
	cryptoSvc := a.cryptoSvc
	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		// For password encryption, prompt for new password with confirmation
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return err
		}
		// Create temporary password provider and crypto service for CA import
		tempPasswordProvider := &password.StaticPasswordProvider{Password: newPassword}
		tempIdentityProvider, err := a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
		if err != nil {
			return fmt.Errorf("failed to create identity provider for CA import: %w", err)
		}
		cryptoSvc = a.cryptoServiceFactory.CreateCryptoService(tempIdentityProvider)
	}

	encryptedKey, err := cryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Successfully imported CA from cert: %s, key: %s", certPath, keyPath))
	return nil
}

// ReencryptKeys re-encrypts all keys in the store with new encryption parameters.
// For password mode: prompts for new password
// For SSH/plugin mode: uses current configuration (allowing manual recipient updates)
func (a *Application) ReencryptKeys(ctx context.Context, force bool, rollback bool) error {
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Create .bak files for all keys before proceeding
	backedUpFiles, err := a.backupKeysToBAK()
	if err != nil {
		return fmt.Errorf("failed to create key backups before re-encryption: %w", err)
	}

	// Create new password provider for this operation if needed
	var newPasswordProvider domain.PasswordProvider = a.passwordProvider
	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		ui.Info("Password encryption detected - prompting for new password")
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return fmt.Errorf("failed to get new password: %w", err)
		}
		newPasswordProvider = &password.StaticPasswordProvider{Password: newPassword}
	} else {
		ui.Info("%s encryption detected - using current configuration", cfg.Encryption.Provider)
		ui.Info("Make sure you've updated ca.yaml with any recipient changes before running this command")
	}

	// Reload config (to pick up any manual changes) and create new identity provider
	cfg, err = a.configLoader.LoadCA()
	if err != nil {
		return fmt.Errorf("failed to reload CA config: %w", err)
	}

	newIdentityProvider, err := a.identityProviderFactory.CreateIdentityProvider(cfg, newPasswordProvider)
	if err != nil {
		return fmt.Errorf("failed to create new identity provider: %w", err)
	}

	// Perform round-trip validation unless forced to skip
	if !force {
		ui.Action("Performing round-trip validation test...")
		if err := a.validationService.ValidateProviderRoundTrip(newIdentityProvider); err != nil {
			a.logger.Log(fmt.Sprintf("Round-trip validation failed: %v", err))
			ui.Warning("Round-trip validation failed: %v", err)
			ui.Warning("This means you may not be able to decrypt your keys after re-encryption.")

			// Prompt user for confirmation
			confirmed, promptErr := a.userInteraction.Confirm("Do you want to proceed anyway? (y/N): ")
			if promptErr != nil {
				return fmt.Errorf("failed to get user confirmation: %w", promptErr)
			}
			if !confirmed {
				return fmt.Errorf("operation cancelled by user")
			}
		} else {
			ui.Action("Round-trip validation successful")
		}
	}

	// Create new crypto service with new identity provider
	newCryptoSvc := a.cryptoServiceFactory.CreateCryptoService(newIdentityProvider)

	return a.reencryptKeysWithService(newCryptoSvc, backedUpFiles, rollback)
}

// reencryptKeysWithService handles the actual key re-encryption process.
func (a *Application) reencryptKeysWithService(newCryptoSvc domain.CryptoService, backedUpFiles []string, rollback bool) error {
	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return fmt.Errorf("failed to list keys in store: %w", err)
	}

	type reEncryptedKey struct {
		path string
		key  []byte
	}
	reEncryptedKeys := make([]reEncryptedKey, 0, len(keyPaths))

	// Decrypt and re-encrypt all keys in memory first
	for _, path := range keyPaths {
		encryptedPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", filepath.Base(path), err)
		}

		// Decrypt with current crypto service
		key, err := a.cryptoSvc.DecryptPrivateKey(encryptedPEM)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return fmt.Errorf("%w for key %s. Aborting. No changes have been made", err, filepath.Base(path))
			}
			return fmt.Errorf("failed to decrypt key %s: %w. Aborting re-encryption", filepath.Base(path), err)
		}

		// Re-encrypt with new crypto service
		reEncrypted, err := newCryptoSvc.EncryptPrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt key %s: %w", filepath.Base(path), err)
		}

		reEncryptedKeys = append(reEncryptedKeys, reEncryptedKey{path: path, key: reEncrypted})
	}

	// Track which files we've successfully written
	var writtenFiles []string

	// Write all re-encrypted keys
	for _, item := range reEncryptedKeys {
		if err := a.store.UpdateEncryptedKey(item.path, item.key); err != nil {
			// On write failure, offer rollback
			a.logger.Log(fmt.Sprintf("Failed to write re-encrypted key %s: %v", filepath.Base(item.path), err))
			return a.handleReencryptionFailure(writtenFiles, backedUpFiles, rollback, fmt.Errorf("failed to write re-encrypted key %s: %w", filepath.Base(item.path), err))
		}
		writtenFiles = append(writtenFiles, item.path)
	}

	// Success - clean up all .bak files
	a.logger.Log("Successfully wrote all re-encrypted keys back to store")
	a.cleanupBackupFiles(backedUpFiles)

	return nil
}

// handleReencryptionFailure offers the user a rollback option and handles cleanup
func (a *Application) handleReencryptionFailure(writtenFiles, backedUpFiles []string, rollback bool, originalErr error) error {
	ui.Error("Re-encryption failed: %v", originalErr)
	ui.Warning("Some keys may have been partially re-encrypted.")

	// Determine if we should rollback
	var confirmed bool
	var err error

	if rollback {
		// --rollback flag provided, automatically rollback
		confirmed = true
		ui.Action("Automatically rolling back due to --rollback flag")
	} else {
		// Ask user for confirmation
		confirmed, err = a.userInteraction.Confirm("Would you like to rollback all changes from .bak files? [y/N]: ")
		if err != nil {
			ui.Error("Failed to get user confirmation: %v", err)
			return fmt.Errorf("FATAL: %w. Manual rollback required from .bak files", originalErr)
		}
	}

	if confirmed {
		ui.Action("Rolling back changes from .bak files...")
		rollbackErrors := 0

		for _, filePath := range backedUpFiles {
			if err := a.store.RestoreFromBackup(filePath); err != nil {
				ui.Error("Failed to restore %s from backup: %v", filepath.Base(filePath), err)
				rollbackErrors++
			}
		}

		// Clean up .bak files after rollback
		a.cleanupBackupFiles(backedUpFiles)

		if rollbackErrors == 0 {
			ui.Success("Successfully rolled back all changes")
			return fmt.Errorf("re-encryption failed but rollback completed successfully: %w", originalErr)
		} else {
			return fmt.Errorf("FATAL: re-encryption failed and rollback had %d errors. Manual recovery may be required: %w", rollbackErrors, originalErr)
		}
	}

	// User declined rollback - leave .bak files for manual recovery
	ui.Warning("Rollback declined. .bak files have been left for manual recovery.")
	return fmt.Errorf("FATAL: %w. .bak files available for manual recovery", originalErr)
}

// cleanupBackupFiles removes all .bak files
func (a *Application) cleanupBackupFiles(backedUpFiles []string) {
	for _, filePath := range backedUpFiles {
		if err := a.store.RemoveBackupFile(filePath); err != nil {
			a.logger.Log(fmt.Sprintf("Warning: failed to remove backup file for %s: %v", filepath.Base(filePath), err))
		}
	}
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
		a.logger.Log(fmt.Sprintf("Using existing key for '%s'", hostID))
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

	hostCert, err := a.cryptoSvc.CreateHostCertificate(&hostCfg, caCert, caKey, hostKey.Public())
	if err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Created certificate for '%s'", hostID))
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
	if err := a.store.SaveHostCert(hostID, certPEM); err != nil {
		return err
	}

	if err := a.exportHostFiles(hostID, hostCert, caCert); err != nil {
		return err
	}

	if shouldDeploy {
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
		if err := a.writeFileWithDir(certPath, a.cryptoSvc.EncodeCertificateToPEM(hostCert), 0644); err != nil {
			return fmt.Errorf("failed to export certificate: %w", err)
		}
		a.logger.Log(fmt.Sprintf("Exported certificate to %s", certPath))
	}

	// Export chain
	if hostCfg.Export.Chain != "" {
		chainPath := a.resolvePath(hostCfg.Export.Chain)
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		caCertPEM := a.cryptoSvc.EncodeCertificateToPEM(caCert)
		chain := bytes.Join([][]byte{hostCertPEM, caCertPEM}, []byte{})
		if err := a.writeFileWithDir(chainPath, chain, 0644); err != nil {
			return fmt.Errorf("failed to export chain: %w", err)
		}
		a.logger.Log(fmt.Sprintf("Exported certificate chain to %s", chainPath))
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

	if strings.TrimSpace(hostCfg.Deploy.Command) == "" {
		return domain.ErrNoDeployCommand
	}

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

	// Perform variable substitution on the command
	substitutedCommand := replacer.Replace(hostCfg.Deploy.Command)

	// Create shell script with safety flags
	shellScript := "set -euo pipefail\n" + substitutedCommand

	// Execute via shell
	output, err := a.commander.Execute("bash", "-c", shellScript)
	if err != nil {
		return fmt.Errorf("deploy command failed: %w\nOutput:\n%s", err, string(output))
	}
	a.logger.Log(fmt.Sprintf("Successfully executed deploy command for '%s'", hostID))

	// Display output to user if there's any
	if len(output) > 0 {
		fmt.Print(string(output))
		if !strings.HasSuffix(string(output), "\n") {
			fmt.Println()
		}
	}

	return nil
}

// ListHosts returns information about all hosts (configured and/or stored).
func (a *Application) ListHosts(ctx context.Context) ([]*domain.HostInfo, error) {
	// Load configured hosts
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}

	// Get hosts from store
	storeHostIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}

	// Create sets for efficient lookup
	configuredHosts := make(map[string]domain.HostConfig)
	for id, cfg := range hostsCfg.Hosts {
		configuredHosts[id] = cfg
	}

	storedHosts := make(map[string]bool)
	for _, id := range storeHostIDs {
		storedHosts[id] = true
	}

	// Collect all unique host IDs
	allHostIDs := make(map[string]bool)
	for id := range configuredHosts {
		allHostIDs[id] = true
	}
	for id := range storedHosts {
		allHostIDs[id] = true
	}

	infoList := make([]*domain.HostInfo, 0, len(allHostIDs))

	for hostID := range allHostIDs {
		_, isConfigured := configuredHosts[hostID]
		isStored := storedHosts[hostID]

		var status domain.HostStatus
		var commonName string
		var notAfter time.Time
		var daysRemaining int64

		var keyAlgorithm, hashAlgorithm string
		var keyLength int

		if isStored && isConfigured {
			// Host is both stored and configured
			status = domain.HostStatusIssued
			cert, err := a.store.LoadHostCert(hostID)
			if err != nil {
				a.logger.Error(fmt.Sprintf("Could not load certificate for host '%s', skipping: %v", hostID, err))
				continue
			}
			commonName = cert.Subject.CommonName
			notAfter = cert.NotAfter
			daysRemaining = int64(time.Until(cert.NotAfter).Hours() / 24)
			keyAlgorithm = cert.PublicKeyAlgorithm.String()
			keyLength = getKeyLength(cert.PublicKey)
			hashAlgorithm = cert.SignatureAlgorithm.String()
		} else if isStored && !isConfigured {
			// Host exists in store but not in config (orphaned)
			status = domain.HostStatusOrphaned
			cert, err := a.store.LoadHostCert(hostID)
			if err != nil {
				a.logger.Error(fmt.Sprintf("Could not load certificate for host '%s', skipping: %v", hostID, err))
				continue
			}
			commonName = cert.Subject.CommonName
			notAfter = cert.NotAfter
			daysRemaining = int64(time.Until(cert.NotAfter).Hours() / 24)
			keyAlgorithm = cert.PublicKeyAlgorithm.String()
			keyLength = getKeyLength(cert.PublicKey)
			hashAlgorithm = cert.SignatureAlgorithm.String()
		} else {
			// Host is configured but not stored
			status = domain.HostStatusConfigured
			hostCfg := configuredHosts[hostID]
			commonName = hostCfg.Subject.CommonName
			// For configured-only hosts, no certificate dates available
		}

		infoList = append(infoList, &domain.HostInfo{
			ID:            hostID,
			CommonName:    commonName,
			NotAfter:      notAfter,
			DaysRemaining: daysRemaining,
			Status:        status,
			KeyAlgorithm:  keyAlgorithm,
			KeyLength:     keyLength,
			HashAlgorithm: hashAlgorithm,
		})
	}

	return infoList, nil
}

// InfoHost returns details for a specific host certificate.
func (a *Application) InfoHost(ctx context.Context, hostID string) (string, error) {
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
	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(hostKey)
	if err != nil {
		return err
	}
	*result = keyPEM
	a.logger.Log(fmt.Sprintf("Exported private key for host '%s'", hostID))
	return nil
}

// ImportHostKey imports an external key for a host.
func (a *Application) ImportHostKey(ctx context.Context, hostID, keyPath string) error {
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
	a.logger.Log(fmt.Sprintf("Successfully imported key for host '%s' from %s", hostID, keyPath))
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

	*result = a.cryptoSvc.EncodeCertificateToPEM(cert)
	a.logger.Log(fmt.Sprintf("Successfully signed CSR from %s", csrPath))
	return nil
}

// CleanHosts removes hosts from the store that are no longer in the config.
func (a *Application) CleanHosts(ctx context.Context, force bool) ([]string, error) {
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
		if err := a.store.DeleteHost(id); err != nil {
			a.logger.Error(fmt.Sprintf("Failed to delete host '%s': %v", id, err))
			// Continue to next host
		} else {
			a.logger.Log(fmt.Sprintf("Successfully deleted host '%s' from store", id))
		}
	}
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

func (a *Application) backupKeysToBAK() ([]string, error) {
	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for backup: %w", err)
	}

	var backedUpFiles []string
	for _, path := range keyPaths {
		if err := a.store.CreateBackupFile(path); err != nil {
			// On backup failure, try to clean up any backups we've already created
			for _, backupPath := range backedUpFiles {
				_ = a.store.RemoveBackupFile(backupPath)
			}
			return nil, fmt.Errorf("failed to create backup for %s: %w", filepath.Base(path), err)
		}
		backedUpFiles = append(backedUpFiles, path)
	}

	return backedUpFiles, nil
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

// getKeyLength extracts the key length in bits from a public key
func getKeyLength(publicKey crypto.PublicKey) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.Size() * 8 // RSA key size is in bytes, convert to bits
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256 // Ed25519 is always 256 bits
	default:
		return 0 // Unknown key type
	}
}
