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

// TestE2E_PasswordEnvironmentVariable tests that REACTOR_CA_PASSWORD environment variable works
func TestE2E_PasswordEnvironmentVariable(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// Setup configuration for localhost certificate like the browsers.yml workflow
	localhostHostsYAML := `hosts:
  localhost:
    alternative_names:
      dns:
        - localhost
        - 127.0.0.1
      ip:
        - 127.0.0.1
        - ::1

    validity:
      years: 1

    key_algorithm: RSA2048
    hash_algorithm: SHA256`

	// Write configs
	e.writeConfig("ca.yaml", testCaYAML)
	e.writeConfig("hosts.yaml", localhostHostsYAML)

	// Initialize PKI
	_, stderr, err := e.run("", "init")
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}

	// Create CA using environment variable password
	_, stderr, err = e.run(testPassword, "ca", "create")
	if err != nil {
		t.Fatalf("ca create failed: %v\n%s", err, stderr)
	}

	// Issue localhost certificate using environment variable password
	stdout, stderr, err := e.run(testPassword, "host", "issue", "localhost")
	if err != nil {
		t.Fatalf("host issue failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Verify certificate was created
	e.assertFileExists("store/hosts/localhost/cert.crt")
	e.assertFileExists("store/hosts/localhost/cert.key.age")

	// Verify certificate contains localhost in SAN
	output, err := e.runOpenSSL("x509", "-in", e.path("store/hosts/localhost/cert.crt"), "-text", "-noout")
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	if !strings.Contains(output, "DNS:localhost") {
		t.Error("Certificate should contain DNS:localhost in Subject Alternative Names")
	}
	if !strings.Contains(output, "IP Address:127.0.0.1") {
		t.Error("Certificate should contain IP Address:127.0.0.1 in Subject Alternative Names")
	}

	// Test certificate validation against CA
	caCertPath := e.path("store/ca/ca.crt")
	certPath := e.path("store/hosts/localhost/cert.crt")

	output, err = e.runOpenSSL("verify", "-CAfile", caCertPath, certPath)
	if err != nil {
		t.Fatalf("Certificate validation failed: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(output, "OK") {
		t.Errorf("Certificate validation should return OK, got: %s", output)
	}

	// Test export private key functionality
	stdout, stderr, err = e.run(testPassword, "host", "export-key", "localhost")
	if err != nil {
		t.Fatalf("host export-key failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Verify exported key is valid PEM format
	if !strings.Contains(stdout, "-----BEGIN PRIVATE KEY-----") {
		t.Error("Exported key should be in PEM format")
	}
	if !strings.Contains(stdout, "-----END PRIVATE KEY-----") {
		t.Error("Exported key should end with PEM footer")
	}

}

// TestE2E_InfoDisplayAllExtensions creates certificates with ALL supported extensions
// and verifies the rendered extension values appear in the CLI info command output
func TestE2E_InfoDisplayAllExtensions(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	// Create comprehensive CA configuration with ALL extension types
	allExtensionsCAYAML := `ca:
  subject:
    common_name: "All Extensions Test CA"
    organization: "Extension Test Org"
    organizational_unit: "Testing Unit"
    country: "US"
    state: "California"
    locality: "San Francisco"
    email: "ca@extensions-test.local"
  validity:
    years: 2
  key_algorithm: "ECP384"
  hash_algorithm: "SHA384"
  extensions:
    # Basic Constraints - CA with path length
    basic_constraints:
      critical: true
      ca: true
      path_length: 3

    # Key Usage - all CA relevant usages
    key_usage:
      critical: true
      digital_signature: true
      key_cert_sign: true
      crl_sign: true
      content_commitment: true

    # Subject Key Identifier
    subject_key_identifier:
      critical: false
      method: "hash"

    # Name Constraints - comprehensive restrictions
    name_constraints:
      critical: true
      permitted_dns_domains:
        - ".extensions-test.local"
        - ".test.internal"
      permitted_ip_ranges:
        - "192.168.100.0/24"
        - "10.10.0.0/16"
      excluded_dns_domains:
        - ".blocked.local"
      permitted_email_addresses:
        - "extensions-test.local"

    # CRL Distribution Points
    crl_distribution_points:
      critical: false
      distribution_points:
        - urls:
            - "http://crl.extensions-test.local/ca.crl"
            - "http://backup-crl.extensions-test.local/ca.crl"
          reasons: [key_compromise, ca_compromise]

    # Custom extensions for testing
    ms_template_name_extension:
      critical: false
      oid: "1.3.6.1.4.1.311.20.2"
      asn1:
        string: "WebServer"

    netscape_comment_extension:
      critical: false
      oid: "2.16.840.1.113730.1.13"
      asn1:
        string: "Generated by ReactorCA for extension testing"

    vendor_test_extension:
      critical: false
      oid: "1.3.6.1.4.1.99999.1"
      asn1:
        string: "Test Extension Value"

encryption:
  provider: "password"
  password:
    env_var: "REACTOR_CA_PASSWORD"
    min_length: 8`

	// Create comprehensive host configuration with ALL extension types
	allExtensionsHostsYAML := `hosts:
  comprehensive-host:
    subject:
      common_name: "comprehensive-host.extensions-test.local"
      organization: "Extension Test Org"
      organizational_unit: "Test Host Unit"
      country: "US"
      state: "California"
      locality: "San Francisco"
      email: "host@extensions-test.local"
    alternative_names:
      dns:
        - "comprehensive-host.extensions-test.local"
        - "web.extensions-test.local"
        - "api.extensions-test.local"
        - "*.wildcard.extensions-test.local"
      ip:
        - "192.168.100.10"
        - "10.10.0.10"
        - "::1"
      email:
        - "admin@extensions-test.local"
        - "webmaster@extensions-test.local"
      uri:
        - "https://comprehensive-host.extensions-test.local"
        - "ldap://ldap.extensions-test.local"
    validity:
      days: 90
    key_algorithm: "ECP256"
    hash_algorithm: "SHA256"
    extensions:
      # Key Usage - end-entity certificate
      key_usage:
        critical: false
        digital_signature: true
        key_encipherment: true
        key_agreement: true
        content_commitment: true

      # Extended Key Usage - comprehensive list
      extended_key_usage:
        critical: false
        server_auth: true
        client_auth: true
        email_protection: true
        time_stamping: true
        ocsp_signing: true
        unknown_ext_key_usage:
          - "1.3.6.1.4.1.311.10.3.4"  # Microsoft EFS encryption
          - "1.3.6.1.5.5.7.3.21"      # SSH client authentication

      # Subject Key Identifier - manual value
      subject_key_identifier:
        critical: false
        method: "manual"
        manual_value: "hex:ABCDEF0123456789ABCDEF0123456789ABCDEF01"

      # Authority Key Identifier
      authority_key_identifier:
        critical: false
        key_id: "hex:FEDCBA9876543210FEDCBA9876543210FEDCBA98"

      # CRL Distribution Points
      crl_distribution_points:
        critical: false
        distribution_points:
          - urls:
              - "http://crl.extensions-test.local/host.crl"
              - "ldap://ldap.extensions-test.local/cn=Host-CRL,dc=example,dc=com"

      # Custom vendor extensions for testing
      vendor_string_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.1"
        asn1:
          string: "Custom vendor string data"

      vendor_int_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.2"
        asn1:
          int: 12345

      vendor_bool_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.3"
        asn1:
          bool: true

      vendor_oid_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.4"
        asn1:
          oid: "1.2.840.113549.1.1.11"`

	// Setup PKI environment with comprehensive extension configurations
	e.writeConfig("ca.yaml", allExtensionsCAYAML)
	e.writeConfig("hosts.yaml", allExtensionsHostsYAML)

	// Initialize and create CA
	_, stderr, err := e.run("", "init")
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}

	_, stderr, err = e.run(testPassword, "ca", "create")
	if err != nil {
		t.Fatalf("ca create failed: %v\n%s", err, stderr)
	}

	// Issue host certificate with all extensions
	_, stderr, err = e.run(testPassword, "host", "issue", "comprehensive-host")
	if err != nil {
		t.Fatalf("host issue failed: %v\n%s", err, stderr)
	}

	// Test CA info command displays extension information
	t.Run("CA_Info_Extensions_Display", func(t *testing.T) {
		stdout, stderr, err := e.run("", "ca", "info")
		if err != nil {
			t.Fatalf("ca info failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Verify extension-specific content appears in the output
		expectedCAContent := []string{
			"extensions-test.local",                   // Name Constraints domain
			"WebServer",                               // Microsoft Template Name
			"Generated by ReactorCA for extension",    // Netscape Comment
			"Test Extension Value",                    // Custom extension value
			"http://crl.extensions-test.local/ca.crl", // CRL Distribution Point
			"Path Length Constraint: 3",               // Basic Constraints path length
			"CA: true",                                // Basic Constraints CA flag
		}

		for _, expected := range expectedCAContent {
			if !strings.Contains(stdout, expected) {
				t.Errorf("CA info output missing expected content: %q", expected)
			}
		}

		t.Logf("CA info output correctly displays extension values")
	})

	// Test Host info command displays extension information
	t.Run("Host_Info_Extensions_Display", func(t *testing.T) {
		stdout, stderr, err := e.run("", "host", "info", "comprehensive-host")
		if err != nil {
			t.Fatalf("host info failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Verify extension-specific content appears in the output
		expectedHostContent := []string{
			"comprehensive-host.extensions-test.local",         // Subject CN and SAN
			"web.extensions-test.local",                        // Additional SAN
			"*.wildcard.extensions-test.local",                 // Wildcard SAN
			"192.168.100.10",                                   // IP SAN
			"admin@extensions-test.local",                      // Email SAN
			"https://comprehensive-host.extensions-test.local", // URI SAN
			"Custom vendor string data",                        // Custom extension string
			"12345",                                            // Custom extension integer
			"ABCDEF0123456789ABCDEF0123456789ABCDEF01",         // Subject Key Identifier (uppercase hex without colons)
			"Server Authentication",                            // Extended Key Usage
			"Client Authentication",                            // Extended Key Usage
			"Email Protection",                                 // Extended Key Usage (correct format)
			"Time Stamping",                                    // Extended Key Usage
			"http://crl.extensions-test.local/host.crl",        // CRL Distribution Point
		}

		for _, expected := range expectedHostContent {
			if !strings.Contains(stdout, expected) {
				t.Errorf("Host info output missing expected content: %q", expected)
			}
		}

		t.Logf("Host info output correctly displays extension values")
	})

	// Test that OpenSSL output also contains extension information
	t.Run("Extensions_OpenSSL_Verification", func(t *testing.T) {
		// Verify CA extensions via OpenSSL
		stdout, stderr, err := e.run("", "ca", "info", "--openssl")
		if err != nil {
			t.Fatalf("ca info --openssl failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		// Check for key extension presence in OpenSSL text output
		opensslCAChecks := []string{
			"CA:TRUE",               // Basic Constraints
			"pathlen:3",             // Basic Constraints path length
			"Certificate Sign",      // Key Usage
			"CRL Sign",              // Key Usage
			"Name Constraints",      // Name Constraints extension
			"extensions-test.local", // Name Constraints domain
			"1.3.6.1.4.1.311.20.2",  // Microsoft Template Name OID
			"1.3.6.1.4.1.99999.1",   // Custom extension OID
		}

		for _, check := range opensslCAChecks {
			if !strings.Contains(stdout, check) {
				t.Errorf("CA OpenSSL output missing: %q", check)
			}
		}

		// Verify Host extensions via OpenSSL
		stdout, stderr, err = e.run("", "host", "info", "comprehensive-host", "--openssl")
		if err != nil {
			t.Fatalf("host info --openssl failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}

		opensslHostChecks := []string{
			"DNS:comprehensive-host.extensions-test.local",         // SAN DNS
			"DNS:*.wildcard.extensions-test.local",                 // SAN wildcard
			"IP Address:192.168.100.10",                            // SAN IP
			"email:admin@extensions-test.local",                    // SAN email
			"URI:https://comprehensive-host.extensions-test.local", // SAN URI
			"TLS Web Server Authentication",                        // Extended Key Usage
			"TLS Web Client Authentication",                        // Extended Key Usage
			"AB:CD:EF:01:23:45:67:89",                              // Subject Key Identifier
			"1.3.6.1.4.1.99999.1",                                  // Custom extension OID
			"1.3.6.1.4.1.99999.2",                                  // Custom extension OID
		}

		for _, check := range opensslHostChecks {
			if !strings.Contains(stdout, check) {
				t.Errorf("Host OpenSSL output missing: %q", check)
			}
		}

		t.Logf("OpenSSL verification confirms extension presence")
	})
}
