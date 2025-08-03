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
	"sort"
	"strings"
	"time"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/pathutil"
	"reactor.de/reactor-ca/internal/ui"
)

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
	sort.Strings(ids)
	return ids, nil
}

// createHostCryptoService creates a crypto service for a specific host,
// potentially with additional recipients merged in.
func (a *Application) createHostCryptoService(caCfg *domain.CAConfig, hostCfg *domain.HostConfig) (domain.CryptoService, error) {
	// Create host-specific identity provider using interface method
	identityProvider, err := a.identityProviderFactory.CreateHostIdentityProvider(caCfg, hostCfg, a.passwordProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create host identity provider: %w", err)
	}

	// Create crypto service with host-specific provider
	return a.cryptoServiceFactory.CreateCryptoService(identityProvider), nil
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

	// Apply inheritance from CA config to host config
	resolvedHostCfg := a.resolveHostConfig(hostCfg, caCfg)

	// Create host-specific crypto service only if host has additional recipients
	var hostCryptoSvc domain.CryptoService
	if hostCfg.Encryption != nil && len(hostCfg.Encryption.AdditionalRecipients) > 0 {
		var err error
		hostCryptoSvc, err = a.createHostCryptoService(caCfg, &hostCfg)
		if err != nil {
			return fmt.Errorf("failed to create host crypto service: %w", err)
		}
	} else {
		// Use base crypto service for hosts without additional recipients
		hostCryptoSvc = a.cryptoSvc
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
		keyAlgoStr := string(resolvedHostCfg.KeyAlgorithm)
		if rekey {
			a.logger.Log(fmt.Sprintf("Rekey requested for '%s'. Generating new %s key.", hostID, keyAlgoStr))
			ui.Info("Generated new %s private key (rekey requested)", keyAlgoStr)
		} else {
			a.logger.Log(fmt.Sprintf("No key found for '%s'. Generating new %s key.", hostID, keyAlgoStr))
			ui.Info("Generated new %s private key", keyAlgoStr)
		}
		hostKey, err = a.cryptoSvc.GeneratePrivateKey(resolvedHostCfg.KeyAlgorithm)
		if err != nil {
			return err
		}
		encryptedHostKey, err := hostCryptoSvc.EncryptPrivateKey(hostKey)
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
		hostKey, err = hostCryptoSvc.DecryptPrivateKey(hostKeyData)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return err
			}
			return fmt.Errorf("failed to decrypt host key: %w", err)
		}
		keyType := ui.GetPrivateKeyTypeDetails(hostKey)
		ui.Info("Reusing existing %s private key", keyType)
	}

	hostCert, err := a.cryptoSvc.CreateHostCertificate(&resolvedHostCfg, caCert, caKey, hostKey.Public())
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
		if err := a.DeployHost(ctx, hostID); err != nil {
			return fmt.Errorf("deployment failed: %w", err)
		}
	}
	a.logger.Log(fmt.Sprintf("Successfully issued certificate for '%s' with %s signature", hostID, resolvedHostCfg.HashAlgorithm))
	ui.Info("Created certificate with %s signature", resolvedHostCfg.HashAlgorithm)
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
		certPath := pathutil.ResolvePath(hostCfg.Export.Cert, a.rootPath)
		if err := a.writeFileWithDir(certPath, a.cryptoSvc.EncodeCertificateToPEM(hostCert), 0644); err != nil {
			return fmt.Errorf("failed to export certificate: %w", err)
		}
		a.logger.Log(fmt.Sprintf("Exported certificate to %s", certPath))
	}

	// Export chain
	if hostCfg.Export.Chain != "" {
		chainPath := pathutil.ResolvePath(hostCfg.Export.Chain, a.rootPath)
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		caCertPEM := a.cryptoSvc.EncodeCertificateToPEM(caCert)
		chain := bytes.Join([][]byte{hostCertPEM, caCertPEM}, []byte{})
		if err := a.writeFileWithDir(chainPath, chain, 0644); err != nil {
			return fmt.Errorf("failed to export chain: %w", err)
		}
		a.logger.Log(fmt.Sprintf("Exported certificate chain to %s", chainPath))
	}

	// Export encrypted private key
	if hostCfg.Export.KeyEncrypted != "" {
		encryptedKeyPath := pathutil.ResolvePath(hostCfg.Export.KeyEncrypted, a.rootPath)
		encryptedKey, err := a.store.LoadHostKey(hostID)
		if err != nil {
			return fmt.Errorf("failed to load encrypted key: %w", err)
		}
		if err := a.writeFileWithDir(encryptedKeyPath, encryptedKey, 0600); err != nil {
			return fmt.Errorf("failed to export encrypted key: %w", err)
		}
		a.logger.Log(fmt.Sprintf("Exported encrypted private key to %s", encryptedKeyPath))
	}

	ui.Success("Successfully issued certificate for \"%s\"", hostID)
	return nil
}

// DeployHost runs the deployment command for a host.
func (a *Application) DeployHost(ctx context.Context, hostID string) error {
	err := a.withHostKey(ctx, hostID, func(hostKey crypto.Signer) error {
		return a.deployHostWithKey(ctx, hostID, hostKey)
	})
	if err != nil {
		return err
	}

	ui.Success("Successfully deployed certificate for \"%s\"", hostID)
	return nil
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
	certPath := pathutil.ResolvePath(hostCfg.Export.Cert, a.rootPath)
	chainPath := pathutil.ResolvePath(hostCfg.Export.Chain, a.rootPath)

	// Handle encrypted key path
	var encryptedKeyPath string
	if hostCfg.Export.KeyEncrypted != "" {
		// Use configured encrypted key export path
		encryptedKeyPath = pathutil.ResolvePath(hostCfg.Export.KeyEncrypted, a.rootPath)
	} else {
		// Create temporary encrypted key file from store
		encryptedKeyData, err := a.store.LoadHostKey(hostID)
		if err != nil {
			return fmt.Errorf("failed to load encrypted key: %w", err)
		}
		tempEncryptedKeyFile, err := os.CreateTemp("", "reactor-ca-encrypted-key-*.age")
		if err != nil {
			return fmt.Errorf("failed to create temp encrypted key file: %w", err)
		}
		defer os.Remove(tempEncryptedKeyFile.Name())
		if err := os.Chmod(tempEncryptedKeyFile.Name(), 0600); err != nil {
			return fmt.Errorf("failed to set permissions on temp encrypted key file: %w", err)
		}
		if _, err := tempEncryptedKeyFile.Write(encryptedKeyData); err != nil {
			return fmt.Errorf("failed to write encrypted key: %w", err)
		}
		if err := tempEncryptedKeyFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp encrypted key file: %w", err)
		}
		encryptedKeyPath = tempEncryptedKeyFile.Name()
	}

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
		"${key_encrypted}", encryptedKeyPath,
	)

	// Perform variable substitution on the command
	substitutedCommand := replacer.Replace(hostCfg.Deploy.Command)

	// Create shell script with safety flags
	shellScript := "set -euo pipefail\n" + substitutedCommand

	// Execute via shell with interactive PTY support
	if err := a.commander.ExecuteInteractive("bash", "-c", shellScript); err != nil {
		return fmt.Errorf("deploy command failed: %w", err)
	}
	a.logger.Log(fmt.Sprintf("Successfully executed deploy command for '%s'", hostID))

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

	// Collect all unique host IDs
	allHostIDs := make(map[string]bool)
	for id := range hostsCfg.Hosts {
		allHostIDs[id] = true
	}
	for _, id := range storeHostIDs {
		allHostIDs[id] = true
	}

	infoList := make([]*domain.HostInfo, 0, len(allHostIDs))
	for hostID := range allHostIDs {
		// Use the new helper function
		hostInfo := a.collectHostInfo(hostID, hostsCfg.Hosts)
		if hostInfo != nil {
			infoList = append(infoList, hostInfo)
		}
	}

	// Sort by host ID alphanumerically
	sort.Slice(infoList, func(i, j int) bool {
		return infoList[i].ID < infoList[j].ID
	})

	return infoList, nil
}

// collectHostInfo gathers all information for a single host from the store and config.
func (a *Application) collectHostInfo(hostID string, configuredHosts map[string]domain.HostConfig) *domain.HostInfo {
	hostInfo := &domain.HostInfo{ID: hostID}
	_, isConfigured := configuredHosts[hostID]

	// Check for cert and key existence
	hasCert, certExistsErr := a.store.HostCertExists(hostID)
	if certExistsErr != nil {
		// If we can't check existence, assume missing
		hostInfo.CertMissing = true
	} else {
		hostInfo.CertMissing = !hasCert
	}

	hasKey, keyExistsErr := a.store.HostKeyExists(hostID)
	if keyExistsErr != nil {
		// If we can't check existence, assume missing
		hostInfo.KeyMissing = true
	} else {
		hostInfo.KeyMissing = !hasKey
	}

	// Try to load certificate if it exists and validate integrity
	if hasCert && certExistsErr == nil {
		cert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			hostInfo.CertBroken = true
		} else {
			hostInfo.CommonName = cert.Subject.CommonName
			hostInfo.NotAfter = cert.NotAfter
			hostInfo.DaysRemaining = int64(time.Until(cert.NotAfter).Hours() / 24)
			hostInfo.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
			hostInfo.KeyLength = getKeyLength(cert.PublicKey)
			hostInfo.HashAlgorithm = cert.SignatureAlgorithm.String()
		}
	}

	// Validate key if it exists
	if hasKey && keyExistsErr == nil {
		if !a.store.ValidateAgeKeyFile(hostID) {
			hostInfo.KeyBroken = true
		}
	}

	// If host is configured, get name from config if we don't have it from cert.
	if isConfigured && hostInfo.CommonName == "" {
		hostInfo.CommonName = configuredHosts[hostID].Subject.CommonName
	}

	// Determine final status based on missing flags (ignore broken for status determination)
	if !hostInfo.CertMissing && !hostInfo.KeyMissing && isConfigured {
		hostInfo.Status = domain.HostStatusIssued
	} else if !hostInfo.CertMissing && !hostInfo.KeyMissing && !isConfigured {
		hostInfo.Status = domain.HostStatusOrphaned
	} else if !hostInfo.KeyMissing && hostInfo.CertMissing && isConfigured {
		hostInfo.Status = domain.HostStatusCertMissing
	} else if !hostInfo.CertMissing && hostInfo.KeyMissing && isConfigured {
		hostInfo.Status = domain.HostStatusKeyMissing
	} else if hostInfo.CertMissing && hostInfo.KeyMissing && isConfigured {
		hostInfo.Status = domain.HostStatusConfigured
	} else if !hostInfo.KeyMissing || !hostInfo.CertMissing {
		// An orphaned key or cert that might not have been caught above
		hostInfo.Status = domain.HostStatusOrphaned
	} else {
		// This case should not be possible if the hostID came from either map.
		// A host must be either in config or in the store.
		return nil
	}

	return hostInfo
}

// InfoHost returns the host certificate for display formatting.
func (a *Application) InfoHost(ctx context.Context, hostID string) (*x509.Certificate, error) {
	return a.store.LoadHostCert(hostID)
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
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Create host-specific crypto service only if host has additional recipients
	var hostCryptoSvc domain.CryptoService
	if hostCfg.Encryption != nil && len(hostCfg.Encryption.AdditionalRecipients) > 0 {
		var err error
		hostCryptoSvc, err = a.createHostCryptoService(caCfg, &hostCfg)
		if err != nil {
			return fmt.Errorf("failed to create host crypto service: %w", err)
		}
	} else {
		// Use base crypto service for hosts without additional recipients
		hostCryptoSvc = a.cryptoSvc
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	encryptedKey, err := hostCryptoSvc.EncryptPrivateKey(key)
	if err != nil {
		return err
	}

	if err := a.store.SaveHostKey(hostID, encryptedKey); err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Successfully imported key for host '%s' from %s", hostID, keyPath))
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

// RenameHost renames a host certificate in both configuration and store.
func (a *Application) RenameHost(ctx context.Context, oldHostID, newHostID string) error {
	// Validate inputs
	if oldHostID == "" || newHostID == "" {
		return fmt.Errorf("%w: host IDs cannot be empty", domain.ErrValidation)
	}
	if oldHostID == newHostID {
		return fmt.Errorf("%w: old and new host IDs must be different", domain.ErrValidation)
	}

	// Validate that old host exists and new host doesn't exist in config
	hostsConfig, err := a.configLoader.LoadHosts()
	if err != nil {
		return fmt.Errorf("failed to load hosts config: %w", err)
	}

	if _, exists := hostsConfig.Hosts[oldHostID]; !exists {
		return fmt.Errorf("%w: host '%s' not found in configuration", domain.ErrHostNotFoundInConfig, oldHostID)
	}

	if _, exists := hostsConfig.Hosts[newHostID]; exists {
		return fmt.Errorf("%w: host '%s' already exists in configuration", domain.ErrValidation, newHostID)
	}

	// Check if host exists in store (optional - we'll rename if it exists)
	storeExists, err := a.store.HostExists(oldHostID)
	if err != nil {
		return fmt.Errorf("failed to check if host exists in store: %w", err)
	}

	// Step 1: Update configuration file first
	a.logger.Info("Updating configuration file...")
	if err := a.configWriter.RenameHost(oldHostID, newHostID); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	ui.Success("Updated configuration: %s → %s", oldHostID, newHostID)

	// Step 2: Rename store directory if it exists
	if storeExists {
		a.logger.Info("Renaming host directory in store...")
		if err := a.store.RenameHost(oldHostID, newHostID); err != nil {
			// Configuration was already updated, so we need to roll back
			a.logger.Error("Failed to rename host in store, attempting to rollback configuration...")
			if rollbackErr := a.configWriter.RenameHost(newHostID, oldHostID); rollbackErr != nil {
				a.logger.Error(fmt.Sprintf("CRITICAL: Failed to rollback configuration change: %v. Manual intervention required.", rollbackErr))
				return fmt.Errorf("failed to rename host in store and rollback failed: store error: %w, rollback error: %v", err, rollbackErr)
			}
			ui.Error("Rolled back configuration change due to store rename failure")
			return fmt.Errorf("failed to rename host directory in store: %w", err)
		}
		ui.Success("Renamed host directory: %s → %s", oldHostID, newHostID)
	} else {
		ui.Info("Host '%s' has no certificate files in store (configuration-only rename)", oldHostID)
	}

	ui.Success("Successfully renamed host: %s → %s", oldHostID, newHostID)
	return nil
}

// ValidateHostKeyAlgorithm checks if existing host key matches the configured algorithm.
// Uses cache-aware approach - only validates if key can be decrypted without authentication prompts.
func (a *Application) ValidateHostKeyAlgorithm(hostID string, hostCfg domain.HostConfig, caCfg *domain.CAConfig) {
	keyExists, err := a.store.HostKeyExists(hostID)
	if err != nil || !keyExists {
		return // Skip if key doesn't exist or can't check
	}

	// Determine correct crypto service (same logic as issueHostWithKey)
	var hostCryptoSvc domain.CryptoService
	if hostCfg.Encryption != nil && len(hostCfg.Encryption.AdditionalRecipients) > 0 {
		var err error
		hostCryptoSvc, err = a.createHostCryptoService(caCfg, &hostCfg)
		if err != nil {
			return // Skip if can't create crypto service
		}
	} else {
		// Use base crypto service for hosts without additional recipients
		hostCryptoSvc = a.cryptoSvc
	}

	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return // Skip if can't load key data
	}

	// Try to decrypt - only validate if succeeds (cached or immediate auth)
	// Same pattern as ValidateCAConfig to avoid authentication prompts
	hostKey, err := hostCryptoSvc.DecryptPrivateKey(hostKeyData)
	if err == nil {
		resolvedCfg := a.resolveHostConfig(hostCfg, caCfg)
		if !a.keyAlgorithmMatches(hostKey, resolvedCfg.KeyAlgorithm) {
			a.logger.Warning("Existing key for '%s' does not match configured algorithm (%s)", hostID, resolvedCfg.KeyAlgorithm)
			ui.Warning("Existing key for '%s' does not match configured algorithm (%s). Use '--rekey' to regenerate.", hostID, resolvedCfg.KeyAlgorithm)
		}
	}
	// If decryption fails (auth required, etc.), silently skip validation
}

// ResolveHostConfig applies inheritance from CA config and validates host config.
func (a *Application) ResolveHostConfig(hostID string, skipKeyWarnings bool) (domain.HostConfig, error) {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return domain.HostConfig{}, err
	}

	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.HostConfig{}, domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return domain.HostConfig{}, err
	}

	resolvedHostCfg := a.resolveHostConfig(hostCfg, caCfg)

	// Check for key algorithm mismatch if host key exists (skip if skipKeyWarnings)
	if !skipKeyWarnings {
		a.ValidateHostKeyAlgorithm(hostID, hostCfg, caCfg)
	}

	return resolvedHostCfg, nil
}

// resolveHostConfig applies inheritance from CA config to host config.
// Returns a new HostConfig with all inherited fields populated.
func (a *Application) resolveHostConfig(hostCfg domain.HostConfig, caCfg *domain.CAConfig) domain.HostConfig {
	resolved := hostCfg // Start with host config

	// Inherit subject fields from CA when not specified in host
	if resolved.Subject.Organization == "" {
		resolved.Subject.Organization = caCfg.CA.Subject.Organization
	}
	if resolved.Subject.OrganizationalUnit == "" {
		resolved.Subject.OrganizationalUnit = caCfg.CA.Subject.OrganizationalUnit
	}
	if resolved.Subject.Country == "" {
		resolved.Subject.Country = caCfg.CA.Subject.Country
	}
	if resolved.Subject.State == "" {
		resolved.Subject.State = caCfg.CA.Subject.State
	}
	if resolved.Subject.Locality == "" {
		resolved.Subject.Locality = caCfg.CA.Subject.Locality
	}
	if resolved.Subject.Email == "" {
		resolved.Subject.Email = caCfg.CA.Subject.Email
	}

	// Inherit hash algorithm from CA when not specified in host
	if resolved.HashAlgorithm == "" {
		resolved.HashAlgorithm = caCfg.CA.HashAlgorithm
	}

	// Inherit key algorithm from CA when not specified in host
	if resolved.KeyAlgorithm == "" {
		resolved.KeyAlgorithm = caCfg.CA.KeyAlgorithm
	}

	return resolved
}

// loadHostKey loads and decrypts a host private key using host-specific encryption.
func (a *Application) loadHostKey(ctx context.Context, hostID string) (crypto.Signer, error) {
	// Load host configuration to get potential additional recipients
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return nil, domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}

	// Create host-specific crypto service only if host has additional recipients
	var hostCryptoSvc domain.CryptoService
	if hostCfg.Encryption != nil && len(hostCfg.Encryption.AdditionalRecipients) > 0 {
		var err error
		hostCryptoSvc, err = a.createHostCryptoService(caCfg, &hostCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create host crypto service: %w", err)
		}
	} else {
		// Use base crypto service for hosts without additional recipients
		hostCryptoSvc = a.cryptoSvc
	}

	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return nil, err
	}

	hostKey, err := hostCryptoSvc.DecryptPrivateKey(hostKeyData)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to decrypt host key: %w", err)
	}
	return hostKey, nil
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
