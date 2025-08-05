package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/ui"
)

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

	// Validate current password access before prompting for new password
	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		err := a.validateCurrentPasswordAccess()
		if err != nil {
			return fmt.Errorf("failed to validate current password: %w", err)
		}
	}

	// Create new password provider for this operation if needed
	var newPasswordProvider domain.PasswordProvider = a.passwordProvider
	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password, cfg.Encryption.Password.MinLength)
		if err != nil {
			return fmt.Errorf("failed to get new password: %w", err)
		}
		newPasswordProvider = &password.StaticPasswordProvider{Password: newPassword}
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
		ui.Action("Performing round-trip en- and decryption test...")
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
			a.logger.Warning("Failed to remove backup file for %s: %v", filepath.Base(filePath), err)
		}
	}
}

// validateCurrentPasswordAccess validates that the current password can decrypt the CA key.
// This provides early validation and better UX by prompting for current password before new password.
func (a *Application) validateCurrentPasswordAccess() error {
	// Try to decrypt the CA key to validate current password
	encryptedCA, err := a.store.LoadCAKey()
	if err != nil {
		return fmt.Errorf("failed to load CA key: %w", err)
	}

	_, err = a.cryptoSvc.DecryptPrivateKey(encryptedCA)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err // Propagate incorrect password error with clear message
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	return nil
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
