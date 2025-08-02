package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/ui"
)

// CreateCA creates a new Certificate Authority.
func (a *Application) CreateCA(ctx context.Context, force bool) error {
	return a.createCA(ctx, force)
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

	// Create identity provider for CA creation - same logic as reencrypt
	var identityProvider domain.IdentityProvider
	var cryptoSvc domain.CryptoService

	if cfg.Encryption.Provider == "" || cfg.Encryption.Provider == "password" {
		// For password encryption, prompt for new password with confirmation
		newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.Encryption.Password.MinLength)
		if err != nil {
			return err
		}
		// Create temporary password provider and identity provider for CA creation
		tempPasswordProvider := &password.StaticPasswordProvider{Password: newPassword}
		identityProvider, err = a.identityProviderFactory.CreateIdentityProvider(cfg, tempPasswordProvider)
		if err != nil {
			return fmt.Errorf("failed to create identity provider for CA creation: %w", err)
		}
	} else {
		// For SSH/plugin encryption, create provider from config like reencrypt does
		var err error
		identityProvider, err = a.identityProviderFactory.CreateIdentityProvider(cfg, a.passwordProvider)
		if err != nil {
			return fmt.Errorf("failed to create identity provider: %w", err)
		}
	}

	cryptoSvc = a.cryptoServiceFactory.CreateCryptoService(identityProvider)

	// Perform round-trip validation unless forced to skip
	if !force {
		ui.Action("Performing round-trip validation test...")
		if err := a.validationService.ValidateProviderRoundTrip(identityProvider); err != nil {
			ui.Warning("Round-trip validation failed: %v", err)
			ui.Warning("This means you may not be able to decrypt your CA key after creation.")

			// Prompt user for confirmation
			confirmed, promptErr := a.userInteraction.Confirm("Do you want to proceed anyway? (y/N): ")
			if promptErr != nil {
				return promptErr
			}
			if !confirmed {
				return fmt.Errorf("operation cancelled by user")
			}
		} else {
			ui.Action("Round-trip validation successful")
		}
	}

	key, err := cryptoSvc.GeneratePrivateKey(cfg.CA.KeyAlgorithm)
	if err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Generated private key with algorithm %s", cfg.CA.KeyAlgorithm))
	keyType := ui.GetPrivateKeyTypeDetails(key)
	ui.Info("Generated new %s private key", keyType)

	cert, err := cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Created self-signed root certificate with %s signature", cfg.CA.HashAlgorithm))
	ui.Info("Created CA certificate with %s signature", cfg.CA.HashAlgorithm)

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

// InfoCA returns the CA certificate for display formatting.
func (a *Application) InfoCA(ctx context.Context) (*x509.Certificate, error) {
	return a.store.LoadCACert()
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

	if !cert.IsCA {
		ui.Warning("Certificate is not marked as a CA certificate (IsCA=false)")
		ui.Warning("This may cause issues when signing certificates")

		confirmed, err := a.userInteraction.Confirm("Continue anyway? (y/N): ")
		if err != nil || !confirmed {
			return fmt.Errorf("operation cancelled")
		}
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		ui.Warning("Certificate lacks CertSign key usage - cannot sign certificates")
		return fmt.Errorf("invalid CA certificate: missing CertSign key usage")
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

// ExportCAKey returns the unencrypted CA private key.
func (a *Application) ExportCAKey(ctx context.Context) ([]byte, error) {
	var result []byte
	err := a.withCAKey(ctx, func(caKey crypto.Signer) error {
		return a.exportCAKeyWithKey(caKey, &result)
	})
	return result, err
}

// exportCAKeyWithKey implements the business logic for exporting the CA key.
func (a *Application) exportCAKeyWithKey(caKey crypto.Signer, result *[]byte) error {
	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(caKey)
	if err != nil {
		return err
	}
	*result = keyPEM
	a.logger.Log("Exported CA private key")
	return nil
}

// ValidateCAConfig checks for CA configuration issues and displays warnings.
func (a *Application) ValidateCAConfig(skipKeyWarnings bool) error {
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Check for key algorithm mismatch if CA key exists (skip if rekeying)
	if !skipKeyWarnings {
		caExists, err := a.store.CAExists()
		if err != nil {
			return err
		}
		if caExists {
			caKeyData, err := a.store.LoadCAKey()
			if err != nil {
				return err
			}
			caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData)
			if err == nil { // Only check if we can decrypt the key
				if !a.keyAlgorithmMatches(caKey, caCfg.CA.KeyAlgorithm) {
					a.logger.Warning("Existing CA key does not match configured algorithm (%s)", caCfg.CA.KeyAlgorithm)
					ui.Warning("Existing CA key does not match configured algorithm (%s). Use 'ca rekey' to regenerate.", caCfg.CA.KeyAlgorithm)
				}
			}
		}
	}

	return nil
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

// withCAKey executes an operation with the CA private key.
func (a *Application) withCAKey(ctx context.Context, operation func(crypto.Signer) error) error {
	caKey, err := a.loadCAKey(ctx)
	if err != nil {
		return err
	}
	return operation(caKey)
}

// keyAlgorithmMatches checks if existing key matches the expected key algorithm.
func (a *Application) keyAlgorithmMatches(key crypto.Signer, expectedAlgo domain.KeyAlgorithm) bool {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch expectedAlgo {
		case domain.RSA2048:
			return k.N.BitLen() == 2048
		case domain.RSA3072:
			return k.N.BitLen() == 3072
		case domain.RSA4096:
			return k.N.BitLen() == 4096
		}
	case *ecdsa.PrivateKey:
		switch expectedAlgo {
		case domain.ECP256:
			return k.Curve == elliptic.P256()
		case domain.ECP384:
			return k.Curve == elliptic.P384()
		case domain.ECP521:
			return k.Curve == elliptic.P521()
		}
	case ed25519.PrivateKey:
		return expectedAlgo == domain.ED25519
	}
	return false
}
