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

	"github.com/serpent213/reactor-ca/internal/domain"
	"github.com/serpent213/reactor-ca/internal/infra/identity"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath         string
	logger           domain.Logger
	configLoader     domain.ConfigLoader
	store            domain.Store
	cryptoSvc        domain.CryptoService
	passwordProvider domain.PasswordProvider
	commander        domain.Commander
	identityProvider domain.IdentityProvider
}

// NewApplication creates a new Application instance.
func NewApplication(
	rootPath string,
	logger domain.Logger,
	configLoader domain.ConfigLoader,
	store domain.Store,
	cryptoSvc domain.CryptoService,
	passwordProvider domain.PasswordProvider,
	commander domain.Commander,
	identityProvider domain.IdentityProvider,
) *Application {
	return &Application{
		rootPath:         rootPath,
		logger:           logger,
		configLoader:     configLoader,
		store:            store,
		cryptoSvc:        cryptoSvc,
		passwordProvider: passwordProvider,
		commander:        commander,
		identityProvider: identityProvider,
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

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
	if err != nil {
		return err
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
	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
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
	a.logger.Log("Renewing CA certificate...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Loading existing CA key...")
	encryptedKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetMasterPassword(ctx, cfg.Encryption.Password)
	if err != nil {
		return err
	}

	key, err := a.cryptoSvc.DecryptPrivateKey(encryptedKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err // Return the specific error for better UX
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	a.logger.Log("Creating new self-signed root certificate...")
	newCert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
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
		confirmed, err := a.passwordProvider.Confirm("Are you sure you want to proceed? [y/N]: ")
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

	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetPasswordForImport(ctx, cfg.Encryption.Password.MinLength)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log("CA imported successfully.")
	return nil
}

// ChangePassword re-encrypts all keys in the store with a new password.
func (a *Application) ChangePassword(ctx context.Context) error {
	a.logger.Log("Starting password change process...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Create a backup before proceeding
	backupPath, err := a.backupStore("passwd-change")
	if err != nil {
		return fmt.Errorf("failed to create store backup before password change: %w", err)
	}
	a.logger.Log(fmt.Sprintf("Created a backup of the store at: %s", backupPath))
	fmt.Printf("A backup of your store has been created at %s\n", backupPath)

	fmt.Println("Enter current master password:")
	oldPassword, err := a.passwordProvider.GetMasterPassword(ctx, cfg.Encryption.Password)
	if err != nil {
		return err
	}

	fmt.Println("Enter new master password:")
	newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
	if err != nil {
		return err
	}

	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return fmt.Errorf("failed to list keys in store: %w", err)
	}

	type reEncryptedKey struct {
		path string
		key  []byte
	}
	reEncryptedKeys := make([]reEncryptedKey, 0, len(keyPaths))

	a.logger.Log(fmt.Sprintf("Decrypting %d keys with old password...", len(keyPaths)))
	for _, path := range keyPaths {
		encryptedPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key %s: %w", path, err)
		}
		key, err := a.cryptoSvc.DecryptPrivateKey(encryptedPEM, oldPassword)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return fmt.Errorf("%w for key %s. Aborting. No changes have been made", err, filepath.Base(path))
			}
			return fmt.Errorf("failed to decrypt key %s: %w. Aborting password change", filepath.Base(path), err)
		}

		reEncrypted, err := a.cryptoSvc.EncryptPrivateKey(key, newPassword)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt key %s: %w", path, err)
		}

		reEncryptedKeys = append(reEncryptedKeys, reEncryptedKey{path: path, key: reEncrypted})
	}

	a.logger.Log("All keys decrypted successfully. Writing re-encrypted keys back to store...")
	for _, item := range reEncryptedKeys {
		if err := a.store.UpdateEncryptedKey(item.path, item.key); err != nil {
			return fmt.Errorf("FATAL: failed to write re-encrypted key %s. Your keys may be in an inconsistent state. PLEASE RESTORE FROM THE BACKUP. Error: %w", item.path, err)
		}
	}

	a.logger.Log("Password change complete. Backup can be removed if everything is working.")
	return nil
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

	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.Encryption.Password)
	if err != nil {
		return err
	}

	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
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
		encryptedHostKey, err := a.cryptoSvc.EncryptPrivateKey(hostKey, password)
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
		hostKey, err = a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
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

	// Get unencrypted key
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.Encryption.Password)
	if err != nil {
		return err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return err
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
	a.logger.Log(fmt.Sprintf("Exporting private key for host '%s'", hostID))
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.Encryption.Password)
	if err != nil {
		return nil, err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return nil, err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return nil, err
	}
	return a.cryptoSvc.EncodeKeyToPEM(hostKey)
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

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.Encryption.Password)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
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
	a.logger.Log(fmt.Sprintf("Signing CSR from %s", csrPath))
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSR file: %w", err)
	}
	csr, err := a.cryptoSvc.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return nil, err
	}
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.Encryption.Password)
	if err != nil {
		return nil, err
	}
	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return nil, err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		return nil, err
	}

	cert, err := a.cryptoSvc.SignCSR(csr, caCert, caKey, validityDays)
	if err != nil {
		return nil, err
	}

	a.logger.Log("CSR signed successfully.")
	return a.cryptoSvc.EncodeCertificateToPEM(cert), nil
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
		confirmed, err := a.passwordProvider.Confirm("Do you want to permanently delete these hosts from the store? [y/N]: ")
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

// createIdentityProvider creates an identity provider based on configuration.
func CreateIdentityProvider(cfg *domain.CAConfig, passwordProvider domain.PasswordProvider) (domain.IdentityProvider, error) {
	switch cfg.Encryption.Provider {
	case "", "password":
		return identity.NewPasswordProvider(cfg.Encryption.Password, passwordProvider), nil
	case "ssh":
		provider := identity.NewSSHProvider(cfg.Encryption.SSH)
		if err := provider.Validate(); err != nil {
			return nil, fmt.Errorf("SSH provider validation failed: %w", err)
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported encryption provider: %s", cfg.Encryption.Provider)
	}
}
