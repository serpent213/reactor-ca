package app

import (
	"context"
	"crypto"
	"fmt"
	"os"
)

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
