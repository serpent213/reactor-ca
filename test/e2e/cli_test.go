//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"reactor.de/reactor-ca/internal/domain"
)

// TestE2E_InitConfig tests the basic workflow using generated config files from init.
func TestE2E_InitConfig(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// 1. Init (generates default config files)
	_, stderr, err := e.run("", "init")
	if err != nil {
		t.Fatalf("`init` command failed: %v\n%s", err, stderr)
	}
	e.assertFileExists("config/ca.yaml")
	e.assertFileExists("config/hosts.yaml")

	// 2. Create CA using generated config
	_, stderr, err = e.run(testPassword, "ca", "create")
	if err != nil {
		t.Fatalf("`ca create` failed: %v\n%s", err, stderr)
	}
	e.assertFileExists("store/ca/ca.crt")
	e.assertFileExists("store/ca/ca.key.age")

	// 3. Issue all host certificates from generated config
	_, stderr, err = e.run(testPassword, "host", "issue", "--all")
	if err != nil {
		t.Fatalf("`host issue --all` failed: %v\n%s", err, stderr)
	}

	// 4. List hosts to verify they were created
	_, stderr, err = e.run("", "host", "list")
	if err != nil {
		t.Fatalf("`host list` failed: %v\n%s", err, stderr)
	}

	// 5. Verify store structure exists for example-host from default config
	e.assertFileExists("store/hosts/web-server-example/cert.crt")
	e.assertFileExists("store/hosts/web-server-example/cert.key.age")
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

	// 11. Verify ca.log contains expected operation entries
	logContent, err := os.ReadFile(e.path("store/ca.log"))
	if err != nil {
		t.Fatalf("Failed to read ca.log: %v", err)
	}

	// Strip datetime prefixes and compare line by line
	logLines := strings.Split(strings.TrimRight(string(logContent), "\n"), "\n")
	var strippedLines []string
	for i, line := range logLines {
		// Strip datetime prefix by removing everything until and including first ": "
		if idx := strings.Index(line, ": "); idx != -1 {
			strippedLines = append(strippedLines, line[idx+2:])
		} else {
			t.Fatalf("Log line %d missing expected datetime prefix with ': ': %q", i+1, line)
		}
	}

	expectedLogLines := []string{
		"Generated private key with algorithm ECP256",
		"Created self-signed root certificate with SHA256 signature",
		"Saved CA certificate and encrypted key to store",
		"No key found for 'web-server'. Generating new ECP256 key.",
		"Exported certificate to " + e.path("exports/web-server.pem"),
		"Exported certificate chain to " + e.path("exports/web-server-chain.pem"),
		"Successfully issued certificate for 'web-server' with SHA256 signature",
		"No key found for 'db-server'. Generating new ECP256 key.",
		"Successfully issued certificate for 'db-server' with SHA256 signature",
		"Using existing key for 'web-server'",
		"Exported certificate to " + e.path("exports/web-server.pem"),
		"Exported certificate chain to " + e.path("exports/web-server-chain.pem"),
		"Successfully issued certificate for 'web-server' with SHA256 signature",
		"Exported private key for host 'web-server'",
	}

	if len(strippedLines) != len(expectedLogLines) {
		t.Fatalf("Expected %d log lines, got %d lines.\nExpected:\n%s\nActual:\n%s",
			len(expectedLogLines), len(strippedLines), strings.Join(expectedLogLines, "\n"), strings.Join(strippedLines, "\n"))
	}

	for i, expected := range expectedLogLines {
		if i >= len(strippedLines) {
			t.Errorf("Missing log line %d: expected %q", i+1, expected)
			continue
		}
		actual := strippedLines[i]
		if actual != expected {
			t.Errorf("Log line %d mismatch:\nExpected: %q\nActual:   %q", i+1, expected, actual)
		}
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

	// 1. Generate an external CA with openssl using config file to avoid duplicate extensions
	configContent := `[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = External Test CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign`

	// Write OpenSSL config file
	configPath := e.path("external_ca.conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write OpenSSL config: %v", err)
	}
	_, err := e.runOpenSSL("req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", "external_ca.key", "-out", "external_ca.crt",
		"-days", "30", "-config", e.path("external_ca.conf"))
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
	var simpleDeployCommand string
	if runtime.GOOS == "windows" {
		simpleDeployCommand = `"DEPLOYED" | Out-File -FilePath "deployment.flag" -Encoding UTF8`
	} else {
		simpleDeployCommand = `echo DEPLOYED > deployment.flag`
	}

	deployHostYAML := fmt.Sprintf(`
hosts:
  deploy-target:
    alternative_names:
      dns: [ "deploy.reactor.test" ]
    validity: { days: 15 }
    deploy:
      command: %q
`, simpleDeployCommand)
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

	// 1b. Test encrypted key deployment
	var deployCommand string
	if runtime.GOOS == "windows" {
		deployCommand = `"Variables available:" | Out-File -FilePath "encrypted-deployment.log" -Encoding UTF8 -NoNewline
        "Cert: ${cert}" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
        "Chain: ${chain}" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
        "Private Key: ${private_key}" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
        "Encrypted Key: ${key_encrypted}" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
        if (Test-Path "${key_encrypted}") {
          $size = (Get-Item "${key_encrypted}").Length
          "Encrypted key exists: $size bytes" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
        } else {
          "ERROR: Encrypted key missing" | Out-File -FilePath "encrypted-deployment.log" -Append -Encoding UTF8
          exit 1
        }`
	} else {
		deployCommand = `echo "Variables available:" > encrypted-deployment.log
        echo "Cert: ${cert}" >> encrypted-deployment.log
        echo "Chain: ${chain}" >> encrypted-deployment.log
        echo "Private Key: ${private_key}" >> encrypted-deployment.log
        echo "Encrypted Key: ${key_encrypted}" >> encrypted-deployment.log
        # Test that encrypted key file exists and has content
        if [ -f "${key_encrypted}" ]; then
          echo "Encrypted key exists: $(wc -c < ${key_encrypted}) bytes" >> encrypted-deployment.log
        else
          echo "ERROR: Encrypted key missing" >> encrypted-deployment.log
          exit 1
        fi`
	}

	encryptedDeployHostYAML := fmt.Sprintf(`
hosts:
  encrypted-deploy-target:
    alternative_names:
      dns: [ "encrypted.reactor.test" ]
    validity: { days: 15 }
    export:
      key_encrypted: "encrypted.key.age"
    deploy:
      command: |
        %s
`, deployCommand)
	e.writeConfig("hosts.yaml", encryptedDeployHostYAML)
	e.runWithCheck(testPassword, "host", "issue", "encrypted-deploy-target", "--deploy")
	e.assertFileExists("encrypted-deployment.log")
	encContent, err := os.ReadFile(e.path("encrypted-deployment.log"))
	if err != nil {
		t.Fatalf("Could not read encrypted deployment log: %v", err)
	}
	logContent := string(encContent)
	if !strings.Contains(logContent, "Encrypted Key: ") {
		t.Errorf("Encrypted key variable missing from deployment log: %s", logContent)
	}
	if !strings.Contains(logContent, "Encrypted key exists: ") {
		t.Errorf("Encrypted key file check failed in deployment log: %s", logContent)
	}
	if strings.Contains(logContent, "ERROR:") {
		t.Errorf("Deployment reported error: %s", logContent)
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

// TestE2E_HostRename covers renaming host certificates.
func TestE2E_HostRename(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.writeConfig("ca.yaml", testCaYAML)
	e.runWithCheck(testPassword, "init")
	e.runWithCheck(testPassword, "ca", "create")

	// 1. Setup initial hosts configuration
	const initialHostsYAML = `# ReactorCA: Host Certificate Configuration
# This file defines the certificates you want to issue for your hosts/services.

hosts:
  old-server:
    # Subject information
    subject:
      common_name: old.reactor.test
      organizational_unit: Testing

    # The names (SANs) the certificate should be valid for
    alternative_names:
      dns:
        - old.reactor.test
        - legacy.reactor.test
      ip:
        - 192.168.1.50

    # Certificate validity period
    validity:
      days: 30

    # Export configuration
    export:
      cert: "exports/old-server.pem"
      chain: "exports/old-server-chain.pem"

  # Another host to ensure we don't affect other entries
  other-server:
    alternative_names:
      dns: [ "other.reactor.test" ]
    validity: { days: 15 }
`

	e.writeConfig("hosts.yaml", initialHostsYAML)

	// 2. Issue certificates for the initial hosts
	e.runWithCheck(testPassword, "host", "issue", "old-server")
	e.runWithCheck(testPassword, "host", "issue", "other-server")

	// Verify initial state
	e.assertFileExists("store/hosts/old-server/cert.crt")
	e.assertFileExists("store/hosts/old-server/cert.key.age")
	e.assertFileExists("store/hosts/other-server/cert.crt")
	e.assertFileExists("store/hosts/other-server/cert.key.age")
	e.assertFileExists("exports/old-server.pem")
	e.assertFileExists("exports/old-server-chain.pem")

	// 3. Read original host cert and key for verification
	originalCert, err := os.ReadFile(e.path("store/hosts/old-server/cert.crt"))
	if err != nil {
		t.Fatalf("Failed to read original cert: %v", err)
	}
	originalKey, err := os.ReadFile(e.path("store/hosts/old-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read original key: %v", err)
	}

	// 4. Perform the rename operation
	stdout, stderr, err := e.run(testPassword, "host", "rename", "old-server", "new-server")
	if err != nil {
		t.Fatalf("`host rename` failed: %v\n%s", err, stderr)
	}

	// Verify the command output contains expected success messages
	if !strings.Contains(stdout, "Updated configuration: old-server → new-server") {
		t.Errorf("Expected configuration update message in output: %s", stdout)
	}
	if !strings.Contains(stdout, "Renamed host directory: old-server → new-server") {
		t.Errorf("Expected directory rename message in output: %s", stdout)
	}
	if !strings.Contains(stdout, "Successfully renamed host: old-server → new-server") {
		t.Errorf("Expected final success message in output: %s", stdout)
	}

	// 5. Verify store directory changes
	e.assertDirDoesNotExist("store/hosts/old-server")
	e.assertDirExists("store/hosts/new-server")
	e.assertFileExists("store/hosts/new-server/cert.crt")
	e.assertFileExists("store/hosts/new-server/cert.key.age")
	// Verify other-server is unaffected
	e.assertFileExists("store/hosts/other-server/cert.crt")

	// 6. Verify that the certificate and key files are identical (moved, not regenerated)
	newCert, err := os.ReadFile(e.path("store/hosts/new-server/cert.crt"))
	if err != nil {
		t.Fatalf("Failed to read renamed cert: %v", err)
	}
	newKey, err := os.ReadFile(e.path("store/hosts/new-server/cert.key.age"))
	if err != nil {
		t.Fatalf("Failed to read renamed key: %v", err)
	}

	if !bytes.Equal(originalCert, newCert) {
		t.Error("Certificate file content changed during rename (should be identical)")
	}
	if !bytes.Equal(originalKey, newKey) {
		t.Error("Private key file content changed during rename (should be identical)")
	}

	// 7. Verify hosts.yaml was updated correctly
	hostsContent, err := os.ReadFile(e.path("config/hosts.yaml"))
	if err != nil {
		t.Fatalf("Failed to read hosts.yaml: %v", err)
	}
	hostsStr := string(hostsContent)

	// Verify old host ID is completely gone
	if strings.Contains(hostsStr, "old-server:") {
		t.Error("hosts.yaml still contains old host ID 'old-server:'")
	}

	// Verify new host ID is present
	if !strings.Contains(hostsStr, "new-server:") {
		t.Error("hosts.yaml does not contain new host ID 'new-server:'")
	}

	// Verify comments and formatting are preserved
	if !strings.Contains(hostsStr, "# ReactorCA: Host Certificate Configuration") {
		t.Error("Header comment was not preserved in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "# Subject information") {
		t.Error("Inline comments were not preserved in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "# The names (SANs) the certificate should be valid for") {
		t.Error("Section comments were not preserved in hosts.yaml")
	}

	// Verify the host configuration content is preserved
	if !strings.Contains(hostsStr, "old.reactor.test") {
		t.Error("Common name was not preserved in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "legacy.reactor.test") {
		t.Error("DNS SAN was not preserved in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "192.168.1.50") {
		t.Error("IP SAN was not preserved in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "organizational_unit: Testing") {
		t.Error("Subject OU was not preserved in hosts.yaml")
	}

	// Verify other-server entry is unaffected
	if !strings.Contains(hostsStr, "other-server:") {
		t.Error("other-server entry was unexpectedly modified in hosts.yaml")
	}
	if !strings.Contains(hostsStr, "other.reactor.test") {
		t.Error("other-server DNS name was unexpectedly modified in hosts.yaml")
	}

	// 8. Test that renamed host works with other commands
	stdout, stderr, err = e.run(testPassword, "host", "info", "new-server")
	if err != nil {
		t.Fatalf("`host info new-server` failed after rename: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "old.reactor.test") {
		t.Error("Host info for renamed host doesn't show expected CN")
	}

	// 9. Test host list includes renamed host
	stdout, stderr, err = e.run(testPassword, "host", "list", "--json")
	if err != nil {
		t.Fatalf("`host list --json` failed after rename: %v\n%s", err, stderr)
	}
	var hosts []*domain.HostInfo
	if err := json.Unmarshal([]byte(stdout), &hosts); err != nil {
		t.Fatalf("Failed to parse JSON from `host list`: %v", err)
	}

	// Find the renamed host in the list
	var foundNewServer bool
	var foundOldServer bool
	for _, host := range hosts {
		if host.ID == "new-server" {
			foundNewServer = true
			if host.CommonName != "old.reactor.test" {
				t.Errorf("Expected CN 'old.reactor.test' for new-server, got '%s'", host.CommonName)
			}
		}
		if host.ID == "old-server" {
			foundOldServer = true
		}
	}

	if !foundNewServer {
		t.Error("new-server not found in host list after rename")
	}
	if foundOldServer {
		t.Error("old-server still appears in host list after rename")
	}

	// 10. Test error cases
	// Try to rename to existing host
	_, stderr, err = e.run(testPassword, "host", "rename", "new-server", "other-server")
	if err == nil {
		t.Fatal("Expected error when renaming to existing host ID, but command succeeded")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("Expected 'already exists' error message, got: %s", stderr)
	}

	// Try to rename non-existent host
	_, stderr, err = e.run(testPassword, "host", "rename", "nonexistent", "something")
	if err == nil {
		t.Fatal("Expected error when renaming non-existent host, but command succeeded")
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("Expected 'not found' error message, got: %s", stderr)
	}

	// 11. Test configuration-only rename (host with no certificates)
	const configOnlyHostYAML = `# ReactorCA: Host Certificate Configuration

hosts:
  new-server:
    subject:
      common_name: old.reactor.test
      organizational_unit: Testing
    alternative_names:
      dns:
        - old.reactor.test
        - legacy.reactor.test
      ip:
        - 192.168.1.50
    validity:
      days: 30
    export:
      cert: "exports/old-server.pem"
      chain: "exports/old-server-chain.pem"

  other-server:
    alternative_names:
      dns: [ "other.reactor.test" ]
    validity: { days: 15 }

  config-only-host:
    alternative_names:
      dns: [ "config.reactor.test" ]
    validity: { days: 7 }
`

	e.writeConfig("hosts.yaml", configOnlyHostYAML)

	// Rename a host that exists only in config (no certificates)
	stdout, stderr, err = e.run(testPassword, "host", "rename", "config-only-host", "renamed-config-host")
	if err != nil {
		t.Fatalf("`host rename` failed for config-only host: %v\n%s", err, stderr)
	}

	// Should mention it's configuration-only
	if !strings.Contains(stdout, "configuration-only rename") {
		t.Errorf("Expected configuration-only message for host with no certificates: %s", stdout)
	}

	// Verify the rename worked in config
	hostsContent, _ = os.ReadFile(e.path("config/hosts.yaml"))
	hostsStr = string(hostsContent)
	if strings.Contains(hostsStr, "config-only-host:") {
		t.Error("hosts.yaml still contains old config-only host ID")
	}
	if !strings.Contains(hostsStr, "renamed-config-host:") {
		t.Error("hosts.yaml does not contain new config-only host ID")
	}
}
