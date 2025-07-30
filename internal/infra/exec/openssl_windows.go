//go:build windows

package exec

import (
	"fmt"
	"os"
	"os/exec"
)

// ExecOpenSSLCertInfo executes openssl to display certificate information on Windows.
func ExecOpenSSLCertInfo(certPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", certPath)
	}

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		return fmt.Errorf("openssl not found in PATH: %w", err)
	}

	cmd := exec.Command(opensslPath, "x509", "-in", certPath, "-text", "-noout")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		// Exit with the same code as openssl
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}

	return nil
}
