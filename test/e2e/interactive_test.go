//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
)

// TestE2E_OpenSSLInfoCommands tests ca info --openssl and host info --openssl commands
func TestE2E_OpenSSLInfoCommands(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// Setup PKI environment with CA and host certificate
	e.writeConfig("ca.yaml", testCaYAML)
	e.writeConfig("hosts.yaml", testHostsYAML)

	// Initialize and create CA
	_, stderr, err := e.run("", "init")
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}

	_, stderr, err = e.run(testPassword, "ca", "create")
	if err != nil {
		t.Fatalf("ca create failed: %v\n%s", err, stderr)
	}

	// Issue a host certificate
	_, stderr, err = e.run(testPassword, "host", "issue", "web-server")
	if err != nil {
		t.Fatalf("host issue failed: %v\n%s", err, stderr)
	}

	// Test ca info --openssl
	t.Run("CA_Info_OpenSSL", func(t *testing.T) {
		stdout, stderr, err := e.run("", "ca", "info", "--openssl")
		if err != nil {
			t.Fatalf("ca info --openssl failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Verify we get openssl x509 output format
		if !strings.Contains(stdout, "Certificate:") {
			t.Error("Expected 'Certificate:' in openssl output")
		}
		if !strings.Contains(stdout, "Subject:") {
			t.Error("Expected 'Subject:' in openssl output")
		}
		if !strings.Contains(stdout, "Issuer:") {
			t.Error("Expected 'Issuer:' in openssl output")
		}
		if !strings.Contains(stdout, "Validity") {
			t.Error("Expected 'Validity' section in openssl output")
		}
		cnRegex := regexp.MustCompile(`CN ?= ?Reactor Test CA`)
		if !cnRegex.MatchString(stdout) {
			t.Error("Expected CA common name in openssl output")
		}

		// Verify no ReactorCA UI output when using --openssl
		if strings.Contains(stdout, "✓") || strings.Contains(stdout, "Retrieving") {
			t.Error("Should not contain ReactorCA UI elements with --openssl flag")
		}
	})

	// Test host info --openssl
	t.Run("Host_Info_OpenSSL", func(t *testing.T) {
		stdout, stderr, err := e.run("", "host", "info", "web-server", "--openssl")
		if err != nil {
			t.Fatalf("host info --openssl failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Verify we get openssl x509 output format
		if !strings.Contains(stdout, "Certificate:") {
			t.Error("Expected 'Certificate:' in openssl output")
		}
		if !strings.Contains(stdout, "Subject:") {
			t.Error("Expected 'Subject:' in openssl output")
		}
		if !strings.Contains(stdout, "Issuer:") {
			t.Error("Expected 'Issuer:' in openssl output")
		}
		if !strings.Contains(stdout, "X509v3 Subject Alternative Name:") {
			t.Error("Expected SAN extension in host certificate")
		}

		// Verify host-specific content
		if !strings.Contains(stdout, "web.reactor.test") {
			t.Error("Expected host DNS name in certificate")
		}
		if !strings.Contains(stdout, "192.168.1.10") {
			t.Error("Expected host IP address in certificate")
		}

		// Verify no ReactorCA UI output when using --openssl
		if strings.Contains(stdout, "✓") || strings.Contains(stdout, "Retrieving") {
			t.Error("Should not contain ReactorCA UI elements with --openssl flag")
		}
	})

	// Test error handling when certificate doesn't exist
	t.Run("Host_Info_OpenSSL_NotFound", func(t *testing.T) {
		stdout, stderr, err := e.run("", "host", "info", "nonexistent-host", "--openssl")
		if err == nil {
			t.Error("Expected error for nonexistent host certificate")
		}

		// Should get proper error message
		expectedMsg := "Certificate file not found"
		if !strings.Contains(stderr, expectedMsg) && !strings.Contains(stdout, expectedMsg) {
			t.Errorf("Expected error message containing '%s', got stdout: %s, stderr: %s", expectedMsg, stdout, stderr)
		}
	})
}
