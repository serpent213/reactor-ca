//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const (
	testInteractivePassword        = "interactive-test-password-147"
	testInteractiveChangedPassword = "interactive-test-password-369"
	promptTimeout                  = 5 * time.Second
)

// ptyTestEnv provides PTY-based interactive testing for password prompts
type ptyTestEnv struct {
	*testEnv
	ptmx   *os.File
	cmd    *exec.Cmd
	reader *bufio.Reader
}

// newPtyTestEnv creates a new PTY-based test environment
func newPtyTestEnv(t *testing.T) *ptyTestEnv {
	return &ptyTestEnv{
		testEnv: newTestEnv(t),
	}
}

// startInteractiveCommand starts a command with PTY support and returns immediately
func (e *ptyTestEnv) startInteractiveCommand(args ...string) error {
	e.t.Helper()

	cmd := exec.Command(reactorCABin, args...)
	cmd.Dir = e.root
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "REACTOR_CA_ROOT="+e.root)
	// IMPORTANT: Do NOT set REACTOR_CA_PASSWORD - we want interactive prompts

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start PTY command: %w", err)
	}

	e.cmd = cmd
	e.ptmx = ptmx
	e.reader = bufio.NewReader(ptmx)

	return nil
}

// waitForPrompt waits for a specific prompt text to appear and returns the full output
func (e *ptyTestEnv) waitForPrompt(expectedPrompt string) (string, error) {
	e.t.Helper()

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		var output strings.Builder
		buffer := make([]byte, 1024)

		for {
			n, err := e.ptmx.Read(buffer)
			if err != nil {
				if err != io.EOF {
					errCh <- err
				}
				return
			}

			if n > 0 {
				chunk := buffer[:n]
				output.Write(chunk)
				// Echo all output to console for debugging
				fmt.Print(string(chunk))

				if strings.Contains(output.String(), expectedPrompt) {
					resultCh <- output.String()
					return
				}
			}
		}
	}()

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return "", fmt.Errorf("read error: %w", err)
	case <-time.After(promptTimeout):
		return "", fmt.Errorf("timeout waiting for prompt '%s'", expectedPrompt)
	}
}

type readResult struct {
	n   int
	err error
}

// sendPassword sends a password to the PTY and presses enter
func (e *ptyTestEnv) sendPassword(password string) error {
	e.t.Helper()
	_, err := e.ptmx.Write([]byte(password + "\n"))
	return err
}

// cleanup waits for command completion and then closes the PTY
func (e *ptyTestEnv) cleanup() error {
	var cmdErr error
	if e.cmd != nil {
		cmdErr = e.cmd.Wait()
	}
	if e.ptmx != nil {
		e.ptmx.Close()
	}
	return cmdErr
}

// TestE2E_InteractivePasswordPrompts tests password prompts without REACTOR_CA_PASSWORD env var
func TestE2E_InteractivePasswordPrompts(t *testing.T) {
	t.Parallel()
	e := newPtyTestEnv(t)
	defer e.cleanup()

	// 1. Initialize the PKI
	_, stderr, err := e.testEnv.run("", "init")
	if err != nil {
		t.Fatalf("init command failed: %v\n%s", err, stderr)
	}

	// 2. Setup minimal config files with password provider
	caConfig := `
ca:
  subject:
    common_name: "Interactive Test CA"
    organization: "Test Corp"
    country: "US"
  validity:
    days: 30
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "password"
  password:
    min_length: 8
`
	hostsConfig := `
hosts:
  web-server:
    subject:
      common_name: "test-server.local"
    subject_alt_names:
      dns_names: ["test-server.local", "localhost"]
    validity:
      days: 90
    key_algorithm: "ECP256"
`
	e.writeConfig("ca.yaml", caConfig)
	e.writeConfig("hosts.yaml", hostsConfig)

	// 3. Test CA creation with interactive password prompts
	t.Run("CA_Create_Interactive", func(t *testing.T) {
		err := e.startInteractiveCommand("ca", "create")
		if err != nil {
			t.Fatalf("Failed to start ca create command: %v", err)
		}

		// Wait for initial password prompt
		output, err := e.waitForPrompt("Enter new CA password: ")
		if err != nil {
			t.Fatalf("Failed to get initial password prompt: %v", err)
		}
		t.Logf("Got initial prompt output: %s", output)

		// Send password
		err = e.sendPassword(testInteractivePassword)
		if err != nil {
			t.Fatalf("Failed to send password: %v", err)
		}

		// Wait for confirmation prompt
		output, err = e.waitForPrompt("Confirm Password: ")
		if err != nil {
			t.Fatalf("Failed to get confirmation prompt: %v", err)
		}
		t.Logf("Got confirmation prompt output: %s", output)

		// Send password confirmation
		err = e.sendPassword(testInteractivePassword)
		if err != nil {
			t.Fatalf("Failed to send password confirmation: %v", err)
		}

		// Wait for command completion
		err = e.cleanup()
		if err != nil {
			t.Fatalf("CA create command failed: %v", err)
		}

		// Verify CA files were created
		e.assertFileExists("store/ca/ca.crt")
		e.assertFileExists("store/ca/ca.key.age")
	})
}

// TestE2E_InteractiveHostIssue tests host certificate issuance with password prompt
func TestE2E_InteractiveHostIssue(t *testing.T) {
	t.Parallel()
	e := newPtyTestEnv(t)
	defer e.cleanup()

	// Setup PKI with existing CA (using env var for initial setup)
	_, stderr, err := e.testEnv.run("", "init")
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}

	caConfig := `
ca:
  subject:
    common_name: "Interactive Test CA"
    organization: "Test Corp"
    country: "US"
  validity:
    days: 30
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "password"
  password:
    min_length: 8
`
	hostsConfig := `
hosts:
  web-server:
    subject:
      common_name: "test-server.local"
    alternative_names:
      dns: ["test-server.local"]
    validity:
      days: 90
    key_algorithm: "ECP256"
`
	e.writeConfig("ca.yaml", caConfig)
	e.writeConfig("hosts.yaml", hostsConfig)

	// Create CA first using env var (to have something to decrypt)
	_, stderr, err = e.testEnv.run(testInteractivePassword, "ca", "create")
	if err != nil {
		t.Fatalf("ca create failed: %v\n%s", err, stderr)
	}

	// Test host issue with interactive password prompt
	t.Run("Host_Issue_Interactive", func(t *testing.T) {
		err := e.startInteractiveCommand("host", "issue", "web-server")
		if err != nil {
			t.Fatalf("Failed to start host issue command: %v", err)
		}

		// Wait for password prompt (to decrypt CA key)
		output, err := e.waitForPrompt("Enter current CA password: ")
		if err != nil {
			t.Fatalf("Failed to get password prompt: %v", err)
		}
		t.Logf("Got password prompt output: %s", output)

		// Send password
		err = e.sendPassword(testInteractivePassword)
		if err != nil {
			t.Fatalf("Failed to send password: %v", err)
		}

		// Wait for command completion
		err = e.cleanup()
		if err != nil {
			t.Fatalf("Host issue command failed: %v", err)
		}

		// Verify host certificate files were created
		e.assertFileExists("store/hosts/web-server/cert.crt")
		e.assertFileExists("store/hosts/web-server/cert.key.age")
	})
}

// TestE2E_InteractiveReencrypt tests ca reencrypt with new password prompts
func TestE2E_InteractiveReencrypt(t *testing.T) {
	t.Parallel()
	e := newPtyTestEnv(t)
	defer e.cleanup()

	// Setup PKI with existing CA and host cert
	_, stderr, err := e.testEnv.run("", "init")
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}

	caConfig := `
ca:
  subject:
    common_name: "Interactive Test CA"
    organization: "Test Corp"
    country: "US"
  validity:
    days: 30
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "password"
  password:
    min_length: 8
`
	hostsConfig := `
hosts:
  web-server:
    subject:
      common_name: "test-server.local"
    alternative_names:
      dns: ["test-server.local"]
    validity:
      days: 90
    key_algorithm: "ECP256"
`
	e.writeConfig("ca.yaml", caConfig)
	e.writeConfig("hosts.yaml", hostsConfig)

	// Create CA using interactive prompts
	err = e.startInteractiveCommand("ca", "create")
	if err != nil {
		t.Fatalf("Failed to start ca create: %v", err)
	}

	// Handle CA creation prompts
	_, err = e.waitForPrompt("Enter new CA password: ")
	if err != nil {
		t.Fatalf("Failed to get CA password prompt: %v", err)
	}
	err = e.sendPassword(testInteractivePassword)
	if err != nil {
		t.Fatalf("Failed to send CA password: %v", err)
	}

	_, err = e.waitForPrompt("Confirm Password: ")
	if err != nil {
		t.Fatalf("Failed to get CA confirmation prompt: %v", err)
	}
	err = e.sendPassword(testInteractivePassword)
	if err != nil {
		t.Fatalf("Failed to send CA confirmation: %v", err)
	}

	err = e.cleanup()
	if err != nil {
		t.Fatalf("CA create failed: %v", err)
	}

	// Create host cert using interactive prompts
	err = e.startInteractiveCommand("host", "issue", "web-server")
	if err != nil {
		t.Fatalf("Failed to start host issue: %v", err)
	}

	_, err = e.waitForPrompt("Enter current CA password: ")
	if err != nil {
		t.Fatalf("Failed to get host password prompt: %v", err)
	}
	err = e.sendPassword(testInteractivePassword)
	if err != nil {
		t.Fatalf("Failed to send host password: %v", err)
	}

	err = e.cleanup()
	if err != nil {
		t.Fatalf("Host issue failed: %v", err)
	}

	// Test reencrypt with interactive password prompts (new order: current → new → confirm)
	t.Run("CA_Reencrypt_Interactive", func(t *testing.T) {
		// Read key files before reencryption to verify they change
		caKeyBefore, err := os.ReadFile(e.path("store/ca/ca.key.age"))
		if err != nil {
			t.Fatalf("Failed to read CA key before reencryption: %v", err)
		}

		hostKeyBefore, err := os.ReadFile(e.path("store/hosts/web-server/cert.key.age"))
		if err != nil {
			t.Fatalf("Failed to read host key before reencryption: %v", err)
		}

		err = e.startInteractiveCommand("ca", "reencrypt")
		if err != nil {
			t.Fatalf("Failed to start ca reencrypt command: %v", err)
		}

		// Wait for current password prompt (new: happens first)
		output, err := e.waitForPrompt("Enter current CA password: ")
		if err != nil {
			t.Fatalf("Failed to get current password prompt: %v", err)
		}
		t.Logf("Got current password prompt output: %s", output)

		// Send current password
		err = e.sendPassword(testInteractivePassword)
		if err != nil {
			t.Fatalf("Failed to send current password: %v", err)
		}

		// Wait for new password prompt
		output, err = e.waitForPrompt("Enter new CA password: ")
		if err != nil {
			t.Fatalf("Failed to get new password prompt: %v", err)
		}
		t.Logf("Got new password prompt output: %s", output)

		// Send new password
		err = e.sendPassword(testInteractiveChangedPassword)
		if err != nil {
			t.Fatalf("Failed to send new password: %v", err)
		}

		// Wait for confirmation prompt
		output, err = e.waitForPrompt("Confirm Password: ")
		if err != nil {
			t.Fatalf("Failed to get confirmation prompt: %v", err)
		}
		t.Logf("Got confirmation prompt output: %s", output)

		// Send password confirmation
		err = e.sendPassword(testInteractiveChangedPassword)
		if err != nil {
			t.Fatalf("Failed to send password confirmation: %v", err)
		}

		// Wait for command completion
		err = e.cleanup()
		if err != nil {
			t.Fatalf("CA reencrypt command failed: %v", err)
		}

		// Verify files still exist and no .bak files remain
		e.assertFileExists("store/ca/ca.key.age")
		e.assertFileExists("store/hosts/web-server/cert.key.age")
		e.assertFileNotExists("store/ca/ca.key.age.bak")
		e.assertFileNotExists("store/hosts/web-server/cert.key.age.bak")

		// Read key files after reencryption and verify they changed
		caKeyAfter, err := os.ReadFile(e.path("store/ca/ca.key.age"))
		if err != nil {
			t.Fatalf("Failed to read CA key after reencryption: %v", err)
		}

		hostKeyAfter, err := os.ReadFile(e.path("store/hosts/web-server/cert.key.age"))
		if err != nil {
			t.Fatalf("Failed to read host key after reencryption: %v", err)
		}

		// Verify the encrypted key files have actually changed content
		if bytes.Equal(caKeyBefore, caKeyAfter) {
			t.Error("CA key file content should have changed after reencryption with new password")
		}

		if bytes.Equal(hostKeyBefore, hostKeyAfter) {
			t.Error("Host key file content should have changed after reencryption with new password")
		}

		t.Logf("Successfully verified that encrypted key files changed after reencryption")
	})
}
