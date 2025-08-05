package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	// reactorCABin holds the path to the compiled test binary.
	reactorCABin string
	// coverDir holds the path for e2e coverage data
	coverDir string
)

const (
	testPassword                   = "super-secret-password-for-testing"
	testInteractivePassword        = "interactive-test-password-147"
	testInteractiveChangedPassword = "interactive-test-password-369"
)

// testPluginMain implements the age plugin protocol for testing.
// This is called when the test binary is executed as "age-plugin-reactortest".
func testPluginMain() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--age-plugin=recipient-v1":
		// Implement encryption flow
		scanner := bufio.NewScanner(os.Stdin)

		// Read add-recipient stanza
		scanner.Scan() // -> add-recipient
		scanner.Scan() // body

		// Read grease stanza
		scanner.Scan() // -> grease-*
		scanner.Scan() // body

		// Read wrap-file-key stanza
		scanner.Scan() // -> wrap-file-key
		scanner.Scan() // body (file key to "encrypt")
		fileKey := scanner.Text()

		// Read extension-labels stanza
		scanner.Scan() // -> extension-labels
		scanner.Scan() // body

		// Read done stanza
		scanner.Scan() // -> done
		scanner.Scan() // body

		// Send recipient-stanza response
		fmt.Printf("-> recipient-stanza 0 test\n")
		fmt.Printf("%s\n", fileKey) // "encrypt" by passing through

		// Wait for ack
		scanner.Scan() // ok
		scanner.Scan() // body

		// Send done
		fmt.Printf("-> done\n\n")

	case "--age-plugin=identity-v1":
		// Implement decryption flow
		scanner := bufio.NewScanner(os.Stdin)

		// Read add-identity stanza
		scanner.Scan() // -> add-identity
		scanner.Scan() // body

		// Read grease stanza
		scanner.Scan() // -> grease-*
		scanner.Scan() // body

		// Read recipient-stanza
		scanner.Scan() // -> recipient-stanza
		scanner.Scan() // body ("encrypted" file key)
		encryptedFileKey := scanner.Text()

		// Read done stanza
		scanner.Scan() // -> done
		scanner.Scan() // body

		// Send file-key response
		fmt.Printf("-> file-key 0\n")
		fmt.Printf("%s\n", encryptedFileKey) // "decrypt" by passing through

		// Wait for ack
		scanner.Scan() // ok
		scanner.Scan() // body

		// Send done
		fmt.Printf("-> done\n\n")

	default:
		os.Exit(1)
	}
}

// TestMain sets up the test environment. It checks for the `openssl` dependency,
// builds the `reactor-ca` binary once, and then runs all tests.
func TestMain(m *testing.M) {
	// Check if we're being run as a plugin
	if filepath.Base(os.Args[0]) == "age-plugin-test" {
		testPluginMain()
		return
	}

	if _, err := exec.LookPath("openssl"); err != nil {
		fmt.Println("WARNING: `openssl` not found in PATH, skipping e2e tests.")
		os.Exit(0)
	}

	tmpDir, err := os.MkdirTemp("", "reactor-ca-build-")
	if err != nil {
		fmt.Printf("Failed to create temp dir for binary: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// Use existing coverage directory for e2e coverage data
	// Get absolute path for project root coverage directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get current directory: %v\n", err)
		os.Exit(1)
	}
	// Navigate to project root (two levels up from test/e2e)
	projectRoot := filepath.Join(cwd, "..", "..")
	coverDir = filepath.Join(projectRoot, "coverage", "e2e-covdata")
	if err := os.MkdirAll(coverDir, 0755); err != nil {
		fmt.Printf("Failed to create coverage dir: %v\n", err)
		os.Exit(1)
	}

	reactorCABin = filepath.Join(tmpDir, "reactor-ca")
	if os.PathSeparator == '\\' {
		reactorCABin += ".exe"
	}

	// Build instrumented binary for coverage collection (Go 1.20+ feature)
	// Change to project root directory for build
	buildCmd := exec.Command("go", "build", "-tags", "e2e", "-cover", "-coverpkg=./...", "-o", reactorCABin, "reactor.de/reactor-ca/cmd/ca")
	buildCmd.Dir = projectRoot
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to build instrumented reactor-ca binary: %v\n%s\n", err, string(output))
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// testEnv provides an isolated environment for a single test.
type testEnv struct {
	root     string
	t        *testing.T
	fakeTime string // RFC3339 timestamp for REACTOR_CA_FAKE_TIME
	timezone string // Timezone for TZ env var
	locale   string // Locale for LC_ALL env var
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root, err := os.MkdirTemp("", "reactor-ca-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp root dir: %v", err)
	}
	t.Cleanup(func() {
		// Keep test dir on failure for debugging
		if !t.Failed() {
			os.RemoveAll(root)
		} else {
			t.Logf("Test failed, keeping test directory at: %s", root)
		}
	})

	if err := os.Mkdir(filepath.Join(root, "config"), 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	return &testEnv{
		root:     root,
		t:        t,
		timezone: "UTC",
		locale:   "C",
	}
}

// setFakeTime sets a specific time for deterministic testing.
// timeStr should be in RFC3339 format (e.g., "2024-01-15T10:30:00Z").
func (e *testEnv) setFakeTime(timeStr string) {
	e.fakeTime = timeStr
}

// setFakeTimeFromTime sets fake time from a time.Time value.
func (e *testEnv) setFakeTimeFromTime(t time.Time) {
	e.fakeTime = t.Format(time.RFC3339)
}

// setTimezone sets the timezone for consistent test results.
func (e *testEnv) setTimezone(tz string) {
	e.timezone = tz
}

// setLocale sets the locale for consistent test results.
func (e *testEnv) setLocale(locale string) {
	e.locale = locale
}

func (e *testEnv) path(p ...string) string {
	return filepath.Join(append([]string{e.root}, p...)...)
}

func (e *testEnv) run(password string, args ...string) (stdout, stderr string, err error) {
	return e.runWithEnv(password, nil, args...)
}

func (e *testEnv) runWithEnv(password string, extraEnv []string, args ...string) (stdout, stderr string, err error) {
	e.t.Helper()
	if reactorCABin == "" {
		return "", "", fmt.Errorf("reactorCABin is empty - TestMain may not have run")
	}
	cmd := exec.Command(reactorCABin, args...)
	cmd.Dir = e.root
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "REACTOR_CA_ROOT="+e.root)
	if password != "" {
		cmd.Env = append(cmd.Env, "REACTOR_CA_PASSWORD="+password)
	}
	// Enable coverage collection for instrumented binary
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	// Set fake time for deterministic testing
	if e.fakeTime != "" {
		cmd.Env = append(cmd.Env, "REACTOR_CA_FAKE_TIME="+e.fakeTime)
	}
	// Set timezone and locale for consistent output formatting
	if e.timezone != "" {
		cmd.Env = append(cmd.Env, "TZ="+e.timezone)
	}
	if e.locale != "" {
		cmd.Env = append(cmd.Env, "LC_ALL="+e.locale)
	}
	// Add any extra environment variables
	if extraEnv != nil {
		cmd.Env = append(cmd.Env, extraEnv...)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

func (e *testEnv) runWithCheck(password string, args ...string) (stdout, stderr string) {
	e.t.Helper()
	stdout, stderr, err := e.run(password, args...)
	if err != nil {
		e.t.Fatalf("Command `reactor-ca %s` failed unexpectedly:\n  err: %v\n  stdout: %s\n  stderr: %s",
			strings.Join(args, " "), err, stdout, stderr)
	}
	return stdout, stderr
}

func (e *testEnv) runOpenSSL(args ...string) (string, error) {
	e.t.Helper()
	cmd := exec.Command("openssl", args...)
	cmd.Dir = e.root
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("openssl command failed: %w\nOutput:\n%s", err, string(output))
	}
	return string(output), nil
}

func (e *testEnv) runCommand(args ...string) error {
	e.t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = e.root
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s command failed: %w\nOutput:\n%s", args[0], err, string(output))
	}
	return nil
}

func (e *testEnv) writeConfig(name string, content string) {
	e.t.Helper()
	path := e.path("config", name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		e.t.Fatalf("Failed to write config file %s: %v", name, err)
	}
}

func (e *testEnv) assertFileExists(path string) {
	e.t.Helper()
	if _, err := os.Stat(e.path(path)); os.IsNotExist(err) {
		e.t.Errorf("Expected file to exist, but it doesn't: %s", path)
	}
}

func (e *testEnv) assertDirExists(path string) {
	e.t.Helper()
	info, err := os.Stat(e.path(path))
	if os.IsNotExist(err) {
		e.t.Errorf("Expected directory to exist, but it doesn't: %s", path)
		return
	}
	if !info.IsDir() {
		e.t.Errorf("Expected path to be a directory, but it's a file: %s", path)
	}
}

func (e *testEnv) assertDirDoesNotExist(path string) {
	e.t.Helper()
	if _, err := os.Stat(e.path(path)); !os.IsNotExist(err) {
		e.t.Errorf("Expected directory to NOT exist, but it does: %s", path)
	}
}

func (e *testEnv) assertFileNotExists(path string) {
	e.t.Helper()
	if _, err := os.Stat(e.path(path)); !os.IsNotExist(err) {
		e.t.Errorf("Expected file to NOT exist, but it does: %s", path)
	}
}

func (e *testEnv) assertFileDoesNotExist(path string) {
	e.t.Helper()
	if _, err := os.Stat(e.path(path)); !os.IsNotExist(err) {
		e.t.Errorf("Expected file to NOT exist, but it does: %s", path)
	}
}

func (e *testEnv) copyTestData(src, dest string) {
	e.t.Helper()
	srcPath := filepath.Join("testdata", src)
	destPath := e.path(dest)

	// Check if source is a directory or file
	info, err := os.Stat(srcPath)
	if err != nil {
		e.t.Fatalf("Failed to stat testdata %s: %v", src, err)
	}

	if info.IsDir() {
		// Copy directory recursively
		err := filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Calculate relative path from source
			relPath, err := filepath.Rel(srcPath, path)
			if err != nil {
				return err
			}
			targetPath := filepath.Join(destPath, relPath)

			if info.IsDir() {
				return os.MkdirAll(targetPath, info.Mode())
			}

			// Copy file
			srcFile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer srcFile.Close()

			destFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			defer destFile.Close()

			_, err = io.Copy(destFile, srcFile)
			if err != nil {
				return err
			}

			return os.Chmod(targetPath, info.Mode())
		})
		if err != nil {
			e.t.Fatalf("Failed to copy testdata directory %s to %s: %v", src, dest, err)
		}
	} else {
		// Copy single file (original behavior)
		data, err := os.ReadFile(srcPath)
		if err != nil {
			e.t.Fatalf("Failed to read testdata file %s: %v", src, err)
		}
		if err := os.WriteFile(destPath, data, 0644); err != nil {
			e.t.Fatalf("Failed to write testdata to dest %s: %v", dest, err)
		}
	}
}

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

func (e *testEnv) createSSHCAConfig(sshKeyPath, sshPubKey string) string {
	// Convert Windows backslashes to forward slashes for YAML
	normalizedPath := filepath.ToSlash(sshKeyPath)

	// Ensure SSH public key is properly quoted if it contains special characters
	pubKey := strings.TrimSpace(sshPubKey)

	return fmt.Sprintf(`ca:
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
`, normalizedPath, pubKey)
}

// Common test configurations
const testCaYAML = `
ca:
  subject:
    common_name: "Reactor Test CA"
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
    env_var: "REACTOR_CA_PASSWORD"
`

const testHostsYAML = `
hosts:
  web-server:
    alternative_names:
      dns: [ "web.reactor.test", "grafana.reactor.test" ]
      ip: [ "192.168.1.10", "10.0.0.10" ]
    validity: { days: 15 }
    export:
      cert: "exports/web-server.pem"
      chain: "exports/web-server-chain.pem"
  db-server:
    alternative_names:
      dns: [ "db.reactor.test" ]
    validity: { days: 15 }
`
