//go:build e2e

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

	"github.com/creack/pty"
)

var (
	// reactorCABin holds the path to the compiled test binary.
	reactorCABin string
)

const (
	testPassword                   = "super-secret-password-for-testing"
	testInteractivePassword        = "interactive-test-password-147"
	testInteractiveChangedPassword = "interactive-test-password-369"
	promptTimeout                  = 5 * time.Second
)

// TestMain sets up the test environment. It checks for the `openssl` dependency,
// builds the `reactor-ca` binary once, and then runs all tests.
func TestMain(m *testing.M) {
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

	reactorCABin = filepath.Join(tmpDir, "reactor-ca")
	if os.PathSeparator == '\\' {
		reactorCABin += ".exe"
	}

	buildCmd := exec.Command("go", "build", "-o", reactorCABin, "reactor.de/reactor-ca/cmd/ca")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to build reactor-ca binary: %v\n%s\n", err, string(output))
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// testEnv provides an isolated environment for a single test.
type testEnv struct {
	root string
	t    *testing.T
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
	return &testEnv{root: root, t: t}
}

func (e *testEnv) path(p ...string) string {
	return filepath.Join(append([]string{e.root}, p...)...)
}

func (e *testEnv) run(password string, args ...string) (stdout, stderr string, err error) {
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
	data, err := os.ReadFile(filepath.Join("testdata", src))
	if err != nil {
		e.t.Fatalf("Failed to read testdata file %s: %v", src, err)
	}
	if err := os.WriteFile(e.path(dest), data, 0644); err != nil {
		e.t.Fatalf("Failed to write testdata to dest %s: %v", dest, err)
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
		// Ensure we end up on a new line
		fmt.Println()
		return result, nil
	case err := <-errCh:
		return "", fmt.Errorf("read error: %w", err)
	case <-time.After(promptTimeout):
		return "", fmt.Errorf("timeout waiting for prompt '%s'", expectedPrompt)
	}
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
    subject:
      common_name: "web.reactor.test"
    alternative_names:
      dns: [ "web.reactor.test", "grafana.reactor.test" ]
      ip: [ "192.168.1.10", "10.0.0.10" ]
    validity: { days: 15 }
    export:
      cert: "exports/web-server.pem"
      chain: "exports/web-server-chain.pem"
  db-server:
    subject:
      common_name: "db.reactor.test"
    validity: { days: 15 }
`
