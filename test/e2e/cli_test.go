//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reactor.de/reactor-ca/internal/domain"
)

var (
	// reactorCABin holds the path to the compiled test binary.
	reactorCABin string
)

const testPassword = "super-secret-password-for-testing"

// TestMain sets up the test environment. It checks for the `openssl` dependency,
// builds the `reactor-ca` binary once, and then runs all tests.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("openssl"); err != nil {
		log.Println("WARNING: `openssl` not found in PATH, skipping e2e tests.")
		os.Exit(0)
	}

	tmpDir, err := os.MkdirTemp("", "reactor-ca-build-")
	if err != nil {
		log.Fatalf("Failed to create temp dir for binary: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	reactorCABin = filepath.Join(tmpDir, "reactor-ca")
	if os.PathSeparator == '\\' {
		reactorCABin += ".exe"
	}

	buildCmd := exec.Command("go", "build", "-o", reactorCABin, "reactor.de/reactor-ca/cmd/ca")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		log.Fatalf("Failed to build reactor-ca binary: %v\n%s", err, string(output))
	}

	os.Exit(m.Run())
}

// TestE2E_CoreWorkflow covers the most common end-to-end scenario:
// init -> create CA -> issue host cert -> list -> info -> export key.
func TestE2E_CoreWorkflow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// 1. Init
	_, stderr, err := e.run("", "init")
	if err != nil {
		t.Fatalf("`init` command failed: %v\n%s", err, stderr)
	}
	e.assertFileExists("config/ca.yaml")
	e.assertFileExists("config/hosts.yaml")

	// 2. Setup config files
	e.writeConfig("ca.yaml", testCaYAML)
	e.writeConfig("hosts.yaml", testHostsYAML)

	// 3. Create CA
	stdout, stderr, err := e.run(testPassword, "ca", "create")
	if err != nil {
		t.Fatalf("`ca create` failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "CA created successfully") {
		t.Errorf("Expected success message from `ca create`, got: %s", stdout)
	}
	e.assertFileExists("store/ca/ca.crt")
	e.assertFileExists("store/ca/ca.key.age")

	// 4. Validate CA cert with openssl
	out, err := e.runOpenSSL("x509", "-in", "store/ca/ca.crt", "-noout", "-subject")
	if err != nil {
		t.Fatalf("openssl failed to read CA cert: %v", err)
	}
	if !strings.Contains(out, "CN = Reactor Test CA") && !strings.Contains(out, "CN=Reactor Test CA") {
		t.Errorf("CA cert has wrong subject: %s", out)
	}

	// 5. Issue a single host certificate
	stdout, stderr, err = e.run(testPassword, "host", "issue", "web-server")
	if err != nil {
		t.Fatalf("`host issue web-server` failed: %v\n%s", err, stderr)
	}
	e.assertFileExists("store/hosts/web-server/cert.crt")
	e.assertFileExists("store/hosts/web-server/cert.key.age")
	e.assertFileExists("exports/web-server.pem")
	e.assertFileExists("exports/web-server-chain.pem")

	// 6. Validate host cert against CA with openssl
	out, err = e.runOpenSSL("verify", "-CAfile", "store/ca/ca.crt", "store/hosts/web-server/cert.crt")
	if err != nil {
		t.Fatalf("openssl failed to verify host cert: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("Host cert verification failed: %s", out)
	}
	// Verify SANs
	out, err = e.runOpenSSL("x509", "-in", "store/hosts/web-server/cert.crt", "-noout", "-text")
	if err != nil {
		t.Fatalf("openssl failed to read host cert: %v", err)
	}
	if !strings.Contains(out, "DNS:web.reactor.test") || !strings.Contains(out, "IP Address:192.168.1.10") {
		t.Errorf("Host cert is missing expected SANs")
	}

	// 7. Issue certs for all remaining hosts
	_, _, err = e.run(testPassword, "host", "issue", "--all")
	if err != nil {
		t.Fatalf("`host issue --all` failed: %v", err)
	}
	e.assertFileExists("store/hosts/db-server/cert.crt")

	// 8. List hosts and check JSON output
	stdout, _, err = e.run(testPassword, "host", "list", "--json")
	if err != nil {
		t.Fatalf("`host list --json` failed: %v", err)
	}
	var hosts []*domain.HostInfo
	if err := json.Unmarshal([]byte(stdout), &hosts); err != nil {
		t.Fatalf("Failed to parse JSON from `host list`: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("Expected 2 hosts in list, got %d", len(hosts))
	}

	// 9. Check info commands
	stdout, _, err = e.run(testPassword, "ca", "info")
	if err != nil {
		t.Fatalf("`ca info` failed: %v", err)
	}
	if !strings.Contains(stdout, "Reactor Test CA") {
		t.Errorf("`ca info` did not contain expected CN")
	}
	stdout, _, err = e.run(testPassword, "host", "info", "web-server")
	if err != nil {
		t.Fatalf("`host info` failed: %v", err)
	}
	if !strings.Contains(stdout, "web.reactor.test") {
		t.Errorf("`host info` did not contain expected CN")
	}

	// 10. Export unencrypted key and validate password protection
	_, _, err = e.run(testPassword, "host", "export-key", "web-server", "-o", "unencrypted.key")
	if err != nil {
		t.Fatalf("`export-key` failed with correct password: %v", err)
	}
	e.assertFileExists("unencrypted.key")
	_, err = e.runOpenSSL("pkey", "-in", "unencrypted.key", "-noout")
	if err != nil {
		t.Fatalf("Exported key is invalid: %v", err)
	}

	// Try with wrong password
	_, stderr, err = e.run("wrong-password", "host", "export-key", "web-server")
	if err == nil {
		t.Fatal("`export-key` succeeded with wrong password, but should have failed")
	}
	if !strings.Contains(stderr, "Incorrect password") {
		t.Errorf("Expected decryption error, got: %s", stderr)
	}
}

// TestE2E_CAManagement covers renewing and re-keying the CA.
func TestE2E_CAManagement(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.writeConfig("ca.yaml", testCaYAML)
	e.runWithCheck(testPassword, "init")

	// Create initial CA
	e.runWithCheck(testPassword, "ca", "create")
	certV1, _ := os.ReadFile(e.path("store/ca/ca.crt"))
	keyV1, _ := os.ReadFile(e.path("store/ca/ca.key.age"))

	// 1. Renew the CA (new cert, same key)
	// Add a small delay to ensure NotBefore/NotAfter timestamps change
	time.Sleep(1 * time.Second)
	e.runWithCheck(testPassword, "ca", "renew")
	certV2, _ := os.ReadFile(e.path("store/ca/ca.crt"))
	keyV2, _ := os.ReadFile(e.path("store/ca/ca.key.age"))

	if bytes.Equal(certV1, certV2) {
		t.Error("`ca renew` did not change the certificate")
	}
	if !bytes.Equal(keyV1, keyV2) {
		t.Error("`ca renew` unexpectedly changed the private key")
	}

	// 2. Rekey the CA (new cert, new key)
	time.Sleep(1 * time.Second)
	e.runWithCheck(testPassword, "ca", "rekey", "--force")
	certV3, _ := os.ReadFile(e.path("store/ca/ca.crt"))
	keyV3, _ := os.ReadFile(e.path("store/ca/ca.key.age"))

	if bytes.Equal(certV2, certV3) {
		t.Error("`ca rekey` did not change the certificate")
	}
	if bytes.Equal(keyV2, keyV3) {
		t.Error("`ca rekey` did not change the private key")
	}

	// Test host rekey instead
	e.writeConfig("hosts.yaml", testHostsYAML)
	e.runWithCheck(testPassword, "host", "issue", "web-server")
	hostCertV1, _ := os.ReadFile(e.path("store/hosts/web-server/cert.crt"))
	hostKeyV1, _ := os.ReadFile(e.path("store/hosts/web-server/cert.key.age"))

	e.runWithCheck(testPassword, "host", "issue", "web-server", "--rekey")
	hostCertV2, _ := os.ReadFile(e.path("store/hosts/web-server/cert.crt"))
	hostKeyV2, _ := os.ReadFile(e.path("store/hosts/web-server/cert.key.age"))

	if bytes.Equal(hostCertV1, hostCertV2) {
		t.Error("`host issue --rekey` did not change the certificate")
	}
	if bytes.Equal(hostKeyV1, hostKeyV2) {
		t.Error("`host issue --rekey` did not change the private key")
	}
}

// TestE2E_ImportAndSign covers importing an external CA and signing a CSR.
func TestE2E_ImportAndSign(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.runWithCheck("", "init")
	e.writeConfig("ca.yaml", testCaYAML)

	// 1. Generate an external CA with openssl
	_, err := e.runOpenSSL("req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", "external_ca.key", "-out", "external_ca.crt",
		"-subj", "/CN=External Test CA", "-days", "30")
	if err != nil {
		t.Fatalf("Failed to generate external CA with openssl: %v", err)
	}

	// 2. Import the external CA
	e.runWithCheck(testPassword, "ca", "import", "--cert", e.path("external_ca.crt"), "--key", e.path("external_ca.key"))
	e.assertFileExists("store/ca/ca.crt")
	e.assertFileExists("store/ca/ca.key.age")

	// 3. Issue a host cert to prove the imported CA works
	e.writeConfig("hosts.yaml", testHostsYAML)
	e.runWithCheck(testPassword, "host", "issue", "web-server")
	out, err := e.runOpenSSL("verify", "-CAfile", "store/ca/ca.crt", "store/hosts/web-server/cert.crt")
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("Failed to verify cert issued by imported CA: %v\n%s", err, out)
	}

	// 4. Sign an external CSR
	e.copyTestData("external.csr", "external.csr")
	e.copyTestData("external.key", "external.key")

	e.runWithCheck(testPassword, "host", "sign-csr", "--csr", e.path("external.csr"), "--out", "signed.crt", "--days", "90")
	e.assertFileExists("signed.crt")

	// 5. Verify the signed CSR
	out, err = e.runOpenSSL("verify", "-CAfile", "store/ca/ca.crt", "signed.crt")
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("Failed to verify signed CSR: %v\n%s", err, out)
	}

	// Verify the subject and public key match the original CSR/key
	out, _ = e.runOpenSSL("x509", "-in", "signed.crt", "-noout", "-subject")
	if !strings.Contains(out, "CN = csr.reactor.local") && !strings.Contains(out, "CN=csr.reactor.local") {
		t.Error("Signed cert has wrong subject")
	}

	pub1, _ := e.runOpenSSL("pkey", "-in", "external.key", "-pubout")
	pub2, _ := e.runOpenSSL("x509", "-in", "signed.crt", "-noout", "-pubkey")
	if pub1 != pub2 {
		t.Error("Public key in signed cert does not match original CSR key")
	}
}

// TestE2E_DeployAndClean covers deployment commands and pruning old hosts.
func TestE2E_DeployAndClean(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.writeConfig("ca.yaml", testCaYAML)
	e.runWithCheck(testPassword, "init")
	e.runWithCheck(testPassword, "ca", "create")

	// 1. Test deployment
	const deployHostYAML = `
hosts:
  deploy-target:
    subject:
      common_name: "deploy.reactor.test"
    validity: { days: 15 }
    deploy:
      command: "echo DEPLOYED > deployment.flag"
`
	e.writeConfig("hosts.yaml", deployHostYAML)
	e.runWithCheck(testPassword, "host", "issue", "deploy-target", "--deploy")
	e.assertFileExists("deployment.flag")
	content, err := os.ReadFile(e.path("deployment.flag"))
	if err != nil {
		t.Fatalf("Could not read deployment flag file: %v", err)
	}
	if !strings.Contains(string(content), "DEPLOYED") {
		t.Errorf("Deployment flag file has wrong content: %s", content)
	}

	// 2. Test cleaning
	e.writeConfig("hosts.yaml", testHostsYAML)
	e.runWithCheck(testPassword, "host", "issue", "--all")
	e.assertDirExists("store/hosts/web-server")
	e.assertDirExists("store/hosts/db-server")

	// Change config to remove a host
	const cleanedHostsYAML = `
hosts:
  web-server:
    subject:
      common_name: "web.reactor.test"
    validity: { days: 15 }
`
	e.writeConfig("hosts.yaml", cleanedHostsYAML)
	e.runWithCheck(testPassword, "host", "clean", "--force")

	e.assertDirExists("store/hosts/web-server")
	e.assertDirDoesNotExist("store/hosts/db-server")
}

// --- Test Helpers ---

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
