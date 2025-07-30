//go:build !windows

package exec

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ExecOpenSSLCertInfo executes openssl to display certificate information using process replacement.
func ExecOpenSSLCertInfo(certPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", certPath)
	}

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		return fmt.Errorf("openssl not found in PATH: %w", err)
	}

	args := []string{"openssl", "x509", "-in", certPath, "-text", "-noout"}

	// Use syscall.Exec to replace current process with openssl
	return syscall.Exec(opensslPath, args, os.Environ())
}
