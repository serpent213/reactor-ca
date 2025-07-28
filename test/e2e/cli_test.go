//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"reactor.de/reactor-ca/internal/domain"
)

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
		"-subj", "/CN=External Test CA", "-days", "30",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-addext", "basicConstraints=critical,CA:TRUE")
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
    alternative_names:
      dns: [ "deploy.reactor.test" ]
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
    alternative_names:
      dns: [ "web.reactor.test" ]
    validity: { days: 15 }
`
	e.writeConfig("hosts.yaml", cleanedHostsYAML)
	e.runWithCheck(testPassword, "host", "clean", "--force")

	e.assertDirExists("store/hosts/web-server")
	e.assertDirDoesNotExist("store/hosts/db-server")
}
