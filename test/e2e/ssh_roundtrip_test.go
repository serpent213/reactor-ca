//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestE2E_SSHRoundtripValidation tests the roundtrip validation with SSH identity provider.
func TestE2E_SSHRoundtripValidation(t *testing.T) {
	t.Parallel()

	t.Run("ValidSSHKey_ValidationPasses", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t)
		e.runWithCheck("", "init")

		// Generate valid SSH key pair
		sshKeyPath, sshPubKey := e.generateSSHKey("test_ed25519")

		// Configure CA with SSH encryption
		caConfig := e.createSSHCAConfig(sshKeyPath, sshPubKey)
		e.writeConfig("ca.yaml", caConfig)

		// CA create should succeed with validation
		stdout, stderr, err := e.run("", "ca", "create")
		if err != nil {
			t.Fatalf("ca create failed with valid SSH key: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Check for validation success message
		if !strings.Contains(stdout, "Round-trip validation successful") {
			t.Errorf("Expected validation success message, got: %s", stdout)
		}
		if !strings.Contains(stdout, "CA created successfully") {
			t.Errorf("Expected CA creation success, got: %s", stdout)
		}

		// Verify CA files exist
		e.assertFileExists("store/ca/ca.crt")
		e.assertFileExists("store/ca/ca.key.age")
	})

	t.Run("MismatchedSSHKeys_ValidationFails", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t)
		e.runWithCheck("", "init")

		// Generate two different SSH key pairs
		sshKeyPath1, _ := e.generateSSHKey("key1")
		_, sshPubKey2 := e.generateSSHKey("key2")

		// Configure CA with mismatched keys (private key 1, public key 2)
		caConfig := e.createSSHCAConfig(sshKeyPath1, sshPubKey2)
		e.writeConfig("ca.yaml", caConfig)

		// CA create should fail due to validation failure + non-TTY prompt error
		stdout, stderr, err := e.run("", "ca", "create")
		if err == nil {
			t.Fatal("ca create should have failed with mismatched SSH keys")
		}

		// Should show validation failure
		if !strings.Contains(stdout, "Round-trip validation failed") {
			t.Errorf("Expected validation failure message, got: %s", stdout)
		}

		// Should fail at the confirmation prompt due to non-TTY
		if !strings.Contains(stderr, "Cannot prompt for confirmation in non-interactive environment") {
			t.Errorf("Expected non-TTY prompt error, got: %s", stderr)
		}

		// CA should not be created
		e.assertFileDoesNotExist("store/ca/ca.crt")
		e.assertFileDoesNotExist("store/ca/ca.key.age")
	})

	t.Run("ForceSkipValidation_CreatesCA", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t)
		e.runWithCheck("", "init")

		// Generate mismatched SSH keys
		sshKeyPath1, _ := e.generateSSHKey("key1")
		_, sshPubKey2 := e.generateSSHKey("key2")

		// Configure CA with mismatched keys
		caConfig := e.createSSHCAConfig(sshKeyPath1, sshPubKey2)
		e.writeConfig("ca.yaml", caConfig)

		// CA create with --force should skip validation and succeed
		stdout, stderr, err := e.run("", "ca", "create", "--force")
		if err != nil {
			t.Fatalf("ca create --force failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Should skip validation entirely
		if strings.Contains(stdout, "Round-trip validation test") {
			t.Errorf("Should have skipped validation with --force, got: %s", stdout)
		}
		if !strings.Contains(stdout, "CA created successfully") {
			t.Errorf("Expected CA creation success, got: %s", stdout)
		}

		// CA files should exist
		e.assertFileExists("store/ca/ca.crt")
		e.assertFileExists("store/ca/ca.key.age")
	})

	t.Run("FullWorkflow_WithSSHEncryption", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t)
		e.runWithCheck("", "init")

		// Generate valid SSH key pair
		sshKeyPath, sshPubKey := e.generateSSHKey("workflow_key")

		// Configure CA and hosts with SSH encryption
		caConfig := e.createSSHCAConfig(sshKeyPath, sshPubKey)
		e.writeConfig("ca.yaml", caConfig)
		e.writeConfig("hosts.yaml", testHostsYAML)

		// Create CA with validation
		e.runWithCheck("", "ca", "create")

		// Issue host certificate (this tests that the SSH-encrypted CA key works)
		e.runWithCheck("", "host", "issue", "web-server")

		// Verify the host cert can be validated against the CA
		out, err := e.runOpenSSL("verify", "-CAfile", "store/ca/ca.crt", "store/hosts/web-server/cert.crt")
		if err != nil || !strings.Contains(out, "OK") {
			t.Fatalf("Host cert verification failed: %v\n%s", err, out)
		}

		// Test that we can export the host key (proves SSH decryption works)
		e.runWithCheck("", "host", "export-key", "web-server", "-o", "exported.key")
		e.assertFileExists("exported.key")

		// Verify exported key is valid
		_, err = e.runOpenSSL("pkey", "-in", "exported.key", "-noout")
		if err != nil {
			t.Fatalf("Exported key is invalid: %v", err)
		}
	})
}

// --- Helper functions ---

// generateSSHKey generates an SSH key pair and returns the private key path and public key content
func (e *testEnv) generateSSHKey(name string) (privateKeyPath string, publicKeyContent string) {
	e.t.Helper()

	privateKeyPath = e.path(fmt.Sprintf("%s_ed25519", name))
	publicKeyPath := e.path(fmt.Sprintf("%s_ed25519.pub", name))

	// Generate Ed25519 key pair using ssh-keygen
	cmd := []string{"ssh-keygen", "-t", "ed25519", "-f", privateKeyPath, "-N", "", "-C", "test@reactor.test"}
	if err := e.runCommand(cmd...); err != nil {
		e.t.Fatalf("Failed to generate SSH key %s: %v", name, err)
	}

	// Read the public key content
	pubKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		e.t.Fatalf("Failed to read public key %s: %v", publicKeyPath, err)
	}

	return privateKeyPath, string(pubKeyBytes)
}

// createSSHCAConfig creates a CA config with SSH encryption
func (e *testEnv) createSSHCAConfig(sshKeyPath, sshPubKey string) string {
	return fmt.Sprintf(`
ca:
  subject:
    common_name: "Reactor SSH Test CA"
    organization: "Test Corp"
    country: "US"
  validity:
    days: 30
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "ssh"
  ssh:
    identity_file: "%s"
    recipients:
      - "%s"
`, sshKeyPath, strings.TrimSpace(sshPubKey))
}

// assertFileDoesNotExist checks that a file does not exist
func (e *testEnv) assertFileDoesNotExist(path string) {
	e.t.Helper()
	if _, err := os.Stat(e.path(path)); !os.IsNotExist(err) {
		e.t.Errorf("Expected file to NOT exist, but it does: %s", path)
	}
}

// runCommand executes a command and returns an error if it fails
func (e *testEnv) runCommand(args ...string) error {
	e.t.Helper()

	// Use exec.Command like the existing runOpenSSL method
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = e.root
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s command failed: %w\nOutput:\n%s", args[0], err, string(output))
	}
	return nil
}
