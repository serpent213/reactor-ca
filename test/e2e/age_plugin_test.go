//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyFile copies a file from src to dst (Windows compatibility helper)
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// TestE2E_AgePluginFlow tests the complete age plugin workflow using a self-hosted plugin.
func TestE2E_AgePluginFlow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// 1. Set up the test plugin by linking the test binary
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get test executable: %v", err)
	}

	pluginPath := e.path("age-plugin-test")
	if os.PathSeparator == '\\' {
		pluginPath += ".exe"
	}

	// Try hard link first, fallback to copy on Windows if needed
	if err := os.Link(testBinary, pluginPath); err != nil {
		// Hard link failed, try copying (Windows compatibility)
		if err := copyFile(testBinary, pluginPath); err != nil {
			t.Fatalf("Failed to create plugin binary: %v", err)
		}
	}
	if err := os.Chmod(pluginPath, 0755); err != nil {
		t.Fatalf("Failed to make plugin executable: %v", err)
	}

	// 2. Create test identity and recipient (using exact format from age library tests)
	identityContent := "AGE-PLUGIN-TEST-10Q32NLXM"
	identityPath := e.path("test-identity")
	if err := os.WriteFile(identityPath, []byte(identityContent), 0600); err != nil {
		t.Fatalf("Failed to create identity file: %v", err)
	}

	recipient := "age1test10qdmzv9q"

	// 3. Set up PATH to include our plugin (per-command, no global modification)
	oldPath := os.Getenv("PATH")
	pluginDir := filepath.Dir(pluginPath)
	pathSep := ":"
	if os.PathSeparator == '\\' {
		pathSep = ";"
	}
	newPath := pluginDir + pathSep + oldPath
	pluginEnv := []string{"PATH=" + newPath}

	// 4. Create CA config with plugin-based encryption
	// Convert Windows paths to forward slashes for YAML compatibility
	yamlIdentityPath := strings.ReplaceAll(identityPath, "\\", "/")

	pluginCaYAML := fmt.Sprintf(`
ca:
  subject:
    common_name: "Reactor Test CA"
    organization: "ReactorCA Testing"
    country: "US"
  validity:
    days: 365
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "plugin"
  plugin:
    identity_file: "%s"
    recipients:
      - "%s"
`, yamlIdentityPath, recipient)

	// 5. Initialize and create CA
	e.runWithCheck("", "init")
	e.writeConfig("ca.yaml", pluginCaYAML)
	e.writeConfig("hosts.yaml", testHostsYAML)

	stdout, stderr, err := e.runWithEnv("", pluginEnv, "ca", "create")
	if err != nil {
		t.Fatalf("`ca create` with plugin failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "CA created successfully") {
		t.Errorf("Expected success message from `ca create`, got: %s", stdout)
	}

	// Verify CA files exist
	e.assertFileExists("store/ca/ca.crt")
	e.assertFileExists("store/ca/ca.key.age")

	// 6. Issue a host certificate
	stdout, stderr, err = e.runWithEnv("", pluginEnv, "host", "issue", "web-server")
	if err != nil {
		t.Fatalf("`host issue` with plugin failed: %v\n%s", err, stderr)
	}

	e.assertFileExists("store/hosts/web-server/cert.crt")
	e.assertFileExists("store/hosts/web-server/cert.key.age")

	// 7. Verify the certificates work (openssl validation)
	out, err := e.runOpenSSL("verify", "-CAfile", "store/ca/ca.crt", "store/hosts/web-server/cert.crt")
	if err != nil {
		t.Fatalf("openssl failed to verify host cert: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("Host cert verification failed: %s", out)
	}

	// 8. Test key export (this uses the plugin for decryption)
	stdout, stderr, err = e.runWithEnv("", pluginEnv, "host", "export-key", "web-server", "-o", "exported.key")
	if err != nil {
		t.Fatalf("`export-key` with plugin failed: %v\n%s", err, stderr)
	}

	e.assertFileExists("exported.key")
	_, err = e.runOpenSSL("pkey", "-in", "exported.key", "-noout")
	if err != nil {
		t.Fatalf("Exported key is invalid: %v", err)
	}

	// 9. Test CA info (requires decrypting CA key)
	stdout, stderr, err = e.runWithEnv("", pluginEnv, "ca", "info")
	if err != nil {
		t.Fatalf("`ca info` with plugin failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Reactor Test CA") {
		t.Errorf("`ca info` did not contain expected CN: %s", stdout)
	}

	// 10. Test that we can successfully use the plugin for multiple operations
	// This demonstrates the plugin works for both encryption and decryption
	stdout, stderr, err = e.runWithEnv("", pluginEnv, "ca", "info")
	if err != nil {
		t.Fatalf("Second `ca info` with plugin failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Reactor Test CA") {
		t.Errorf("Second `ca info` did not contain expected CN: %s", stdout)
	}

	// TODO: Add reencrypt test - currently reencrypt expects current password
	// even for plugin providers, which needs to be fixed in the main codebase
}

// TestE2E_AgePluginError tests error handling when the plugin is not available.
func TestE2E_AgePluginError(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// Create CA config with non-existent plugin
	pluginCaYAML := `
ca:
  subject:
    common_name: "Reactor Test CA"
    organization: "ReactorCA Testing"
    country: "US"
  validity:
    days: 365
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"

encryption:
  provider: "plugin"
  plugin:
    identity_file: "nonexistent-identity"
    recipients:
      - "age1nonexistent1qtest"
`

	e.runWithCheck("", "init")
	e.writeConfig("ca.yaml", pluginCaYAML)

	// Attempt to create CA should fail gracefully (use normal PATH, no plugin available)
	_, stderr, err := e.run("", "ca", "create")
	if err == nil {
		t.Fatal("Expected `ca create` to fail with non-existent plugin, but it succeeded")
	}

	// Should get a meaningful error about the missing identity file
	if !strings.Contains(stderr, "identity file not accessible") {
		t.Errorf("Expected error about missing identity file, got: %s", stderr)
	}
}
