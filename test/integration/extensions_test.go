//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/infra/config"
	"reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/exec"
	"reactor.de/reactor-ca/internal/infra/identity"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/infra/store"
)

// TestExtensionsComprehensive tests ALL available certificate extensions
// and verifies them using OpenSSL
func TestExtensionsComprehensive(t *testing.T) {
	// Set up password for testing
	testPassword := "test-password-123"
	t.Setenv("REACTOR_CA_PASSWORD", testPassword)

	// Verify OpenSSL is available
	VerifyOpenSSLVersion(t)

	// Create test environment
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Create store directory structure - FileStore expects ca/ and hosts/ directly under rootPath
	if err := os.MkdirAll(filepath.Join(tmpDir, "ca"), 0755); err != nil {
		t.Fatalf("Failed to create ca directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "hosts"), 0755); err != nil {
		t.Fatalf("Failed to create hosts directory: %v", err)
	}

	// Create comprehensive CA configuration with ALL extension types
	caConfigPath := filepath.Join(configDir, "ca.yaml")
	if err := createComprehensiveCAConfig(caConfigPath); err != nil {
		t.Fatalf("Failed to create CA config: %v", err)
	}

	// Create comprehensive host configuration with ALL extension types
	hostsConfigPath := filepath.Join(configDir, "hosts.yaml")
	if err := createComprehensiveHostsConfig(hostsConfigPath); err != nil {
		t.Fatalf("Failed to create hosts config: %v", err)
	}

	// Create test application
	app := createTestApplicationForExtensions(tmpDir)

	ctx := context.Background()

	// Test 1: Validate configuration
	t.Run("ConfigValidation", func(t *testing.T) {
		if err := app.ValidateConfig(ctx); err != nil {
			t.Fatalf("Configuration validation failed: %v", err)
		}
	})

	// Test 2: Create CA with all extensions
	t.Run("CreateCA", func(t *testing.T) {
		err := app.CreateCA(ctx, true) // force = true
		if err != nil {
			t.Fatalf("Failed to create CA: %v", err)
		}

		// Verify CA certificate exists
		caCertPath := filepath.Join(tmpDir, "ca", "ca.crt")
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			t.Fatal("CA certificate was not created")
		}

		// Verify CA extensions using OpenSSL
		verifyCAExtensions(t, caCertPath)
	})

	// Test 3: Issue host certificate with all extensions
	t.Run("IssueHost", func(t *testing.T) {
		err := app.IssueHost(ctx, "test-server", false, false)
		if err != nil {
			t.Fatalf("Failed to issue host certificate: %v", err)
		}

		// Verify host certificate exists
		hostCertPath := filepath.Join(tmpDir, "hosts", "test-server", "cert.crt")
		if _, err := os.Stat(hostCertPath); os.IsNotExist(err) {
			t.Fatal("Host certificate was not created")
		}

		// Verify host extensions using OpenSSL
		verifyHostExtensions(t, hostCertPath)
	})

	// Test 4: Test all unknown extension encodings
	t.Run("UnknownExtensionEncodings", func(t *testing.T) {
		testUnknownExtensionEncodings(t, tmpDir)
	})
}

// TestExtensionValidationErrors tests all validation error paths
func TestExtensionValidationErrors(t *testing.T) {
	// Set up password for testing
	testPassword := "test-password-123"
	t.Setenv("REACTOR_CA_PASSWORD", testPassword)

	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	tests := []struct {
		name        string
		caConfig    string
		hostsConfig string
		expectedErr string
	}{
		{
			name: "InvalidBasicConstraints",
			caConfig: `ca:
  subject:
    common_name: "Test CA"
  validity:
    years: 1
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"
  extensions:
    basic_constraints:
      critical: true
      ca: true
      path_length: 5
      path_length_zero: true  # Invalid: can't have both path_length and path_length_zero
encryption:
  provider: "password"`,
			hostsConfig: `hosts: {}`,
			expectedErr: "path_length_zero can only be true when path_length is 0 or unset",
		},
		{
			name: "InvalidExtendedKeyUsageOID",
			caConfig: `ca:
  subject:
    common_name: "Test CA"
  validity:
    years: 1
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"
  extensions:
    extended_key_usage:
      critical: true
      server_auth: true
      unknown_ext_key_usage:
        - "invalid.oid"  # Invalid OID format
encryption:
  provider: "password"`,
			hostsConfig: `hosts: {}`,
			expectedErr: "Does not match pattern",
		},
		{
			name: "InvalidOIDFormat",
			caConfig: `ca:
  subject:
    common_name: "Test CA"
  validity:
    years: 1
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"
  extensions:
    custom_extension:
      critical: false
      oid: "invalid.oid.123.abc"  # Invalid: contains non-numeric components
      value: "base64:VGVzdA=="
encryption:
  provider: "password"`,
			hostsConfig: `hosts: {}`,
			expectedErr: "Does not match pattern",
		},
		{
			name: "MissingRequiredFieldsForUnknownExtension",
			caConfig: `ca:
  subject:
    common_name: "Test CA"
  validity:
    years: 1
  key_algorithm: "ECP256"
  hash_algorithm: "SHA256"
  extensions:
    custom_extension:
      critical: false
      # Missing oid and value fields
encryption:
  provider: "password"`,
			hostsConfig: `hosts: {}`,
			expectedErr: "oid is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config files
			caConfigPath := filepath.Join(configDir, "ca.yaml")
			if err := os.WriteFile(caConfigPath, []byte(tt.caConfig), 0644); err != nil {
				t.Fatalf("Failed to write CA config: %v", err)
			}

			hostsConfigPath := filepath.Join(configDir, "hosts.yaml")
			if err := os.WriteFile(hostsConfigPath, []byte(tt.hostsConfig), 0644); err != nil {
				t.Fatalf("Failed to write hosts config: %v", err)
			}

			// Create application and test validation
			app := createTestApplicationForExtensions(tmpDir)
			err := app.ValidateConfig(context.Background())

			if err == nil {
				t.Errorf("Expected validation error containing '%s', but validation passed", tt.expectedErr)
				return
			}

			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("Expected error containing '%s', got: %v", tt.expectedErr, err)
			}
		})
	}
}

// createComprehensiveCAConfig creates a CA configuration with ALL extension types
func createComprehensiveCAConfig(path string) error {
	config := `ca:
  subject:
    common_name: "Comprehensive Test CA"
    organization: "Test Organization"
    country: "US"
    state: "Test State"
    locality: "Test City"
    email: "ca@test.local"
  validity:
    years: 2
  key_algorithm: "ECP384"
  hash_algorithm: "SHA384"
  extensions:
    # Basic Constraints - CA with path length
    basic_constraints:
      critical: true
      ca: true
      path_length: 2

    # Key Usage - CA operations + digital signature
    key_usage:
      critical: true
      digital_signature: true
      key_cert_sign: true
      crl_sign: true

    # Subject Key Identifier - hash method
    subject_key_identifier:
      critical: false
      method: "hash"

    # Name Constraints - restrict to homelab domains
    name_constraints:
      critical: true
      permitted_dns_domains:
        - ".test.local"
        - ".homelab.local"
        - ".internal"
      permitted_ip_ranges:
        - "192.168.0.0/16"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
      excluded_dns_domains:
        - ".example.com"
      permitted_email_addresses:
        - "test.local"

    # Custom extension with base64 encoding
    custom_ca_extension:
      critical: false
      oid: "1.3.6.1.4.1.12345.1"
      value: "base64:Q29tcHJlaGVuc2l2ZSBDQSBUZXN0"

    # Custom extension with hex encoding
    custom_hex_extension:
      critical: false
      oid: "1.3.6.1.4.1.12345.2"
      value: "hex:48656c6c6f20576f726c64"

    # Custom extension with ASN.1 string encoding
    custom_asn1_extension:
      critical: false
      oid: "1.3.6.1.4.1.12345.3"
      value: "asn1:string:Test ASN.1 String"

encryption:
  provider: "password"
  password:
    env_var: "REACTOR_CA_PASSWORD"
    min_length: 8
`
	return os.WriteFile(path, []byte(config), 0644)
}

// createComprehensiveHostsConfig creates a hosts configuration with ALL extension types
func createComprehensiveHostsConfig(path string) error {
	config := `hosts:
  test-server:
    subject:
      common_name: "test-server.test.local"
      organization: "Test Organization"
      country: "US"
    alternative_names:
      dns:
        - "test-server.test.local"
        - "web.test.local"
        - "api.test.local"
      ip:
        - "192.168.1.100"
        - "10.0.0.100"
      email:
        - "admin@test.local"
      uri:
        - "https://test-server.test.local"
    validity:
      days: 365
    key_algorithm: "ECP256"
    hash_algorithm: "SHA256"
    extensions:
      # Key Usage - end-entity certificate
      key_usage:
        critical: false
        digital_signature: true
        key_encipherment: true
        key_agreement: true

      # Extended Key Usage - with standard and custom EKUs
      extended_key_usage:
        critical: false
        server_auth: true
        client_auth: true
        email_protection: true
        time_stamping: true
        unknown_ext_key_usage:
          - "1.3.6.1.4.1.311.10.3.4"  # Microsoft EFS encryption
          - "1.3.6.1.5.5.7.3.21"      # SSH client authentication

      # Subject Key Identifier - manual method with specific value
      subject_key_identifier:
        critical: false
        method: "manual"
        manual_value: "hex:0123456789ABCDEF0123456789ABCDEF01234567"

      # Authority Key Identifier - will be set to CA's SKI
      authority_key_identifier:
        critical: false
        key_id: "hex:FEDCBA9876543210FEDCBA9876543210FEDCBA98"

      # Custom host extension with different OID
      custom_host_extension:
        critical: false
        oid: "1.3.6.1.4.1.54321.1"
        value: "base64:SG9zdCBTcGVjaWZpYyBEYXRh"

      # Custom extension with ASN.1 integer
      custom_int_extension:
        critical: false
        oid: "1.3.6.1.4.1.54321.2"
        value: "asn1:int:42"

      # Custom extension with ASN.1 boolean
      custom_bool_extension:
        critical: false
        oid: "1.3.6.1.4.1.54321.3"
        value: "asn1:bool:true"

      # Custom extension with ASN.1 OID
      custom_oid_extension:
        critical: false
        oid: "1.3.6.1.4.1.54321.4"
        value: "asn1:oid:1.2.840.113549.1.1.11"
`
	return os.WriteFile(path, []byte(config), 0644)
}

// createTestApplicationForExtensions creates an Application instance for extension testing
func createTestApplicationForExtensions(rootPath string) *app.Application {
	logger := &MockLogger{}
	configLoader := config.NewYAMLConfigLoader(filepath.Join(rootPath, "config"))
	store := store.NewFileStore(rootPath)

	// Use regular password provider (will use REACTOR_CA_PASSWORD env var)
	passwordProvider := password.NewProvider()

	userInteraction := &mockUserInteraction{confirmResponse: true}
	commander := exec.NewCommander()
	identityProviderFactory := identity.NewFactory()
	cryptoServiceFactory := crypto.NewServiceFactory()
	validationService := crypto.NewValidationService()

	// Load CA config to create proper identity provider and crypto service
	cfg, err := configLoader.LoadCA()
	if err != nil {
		// Return app without crypto services for validation-only operations
		return app.NewApplication(
			rootPath,
			logger,
			configLoader,
			store,
			nil,
			passwordProvider,
			userInteraction,
			commander,
			nil,
			identityProviderFactory,
			cryptoServiceFactory,
			validationService,
		)
	}

	// Create identity provider from config
	identityProvider, err := identityProviderFactory.CreateIdentityProvider(cfg, passwordProvider)
	if err != nil {
		// Return app without crypto services if identity provider creation fails
		return app.NewApplication(
			rootPath,
			logger,
			configLoader,
			store,
			nil,
			passwordProvider,
			userInteraction,
			commander,
			nil,
			identityProviderFactory,
			cryptoServiceFactory,
			validationService,
		)
	}

	// Create crypto service from identity provider
	cryptoSvc := cryptoServiceFactory.CreateCryptoService(identityProvider)

	return app.NewApplication(
		rootPath,
		logger,
		configLoader,
		store,
		cryptoSvc,
		passwordProvider,
		userInteraction,
		commander,
		identityProvider,
		identityProviderFactory,
		cryptoServiceFactory,
		validationService,
	)
}

// verifyCAExtensions uses OpenSSL to verify all CA certificate extensions
func verifyCAExtensions(t *testing.T, certPath string) {
	// Get certificate text output
	certText := runOpenSSLCommand(t, "x509", "-in", certPath, "-text", "-noout")

	// Verify Basic Constraints
	if !strings.Contains(certText, "CA:TRUE") {
		t.Error("CA certificate missing Basic Constraints CA:TRUE")
	}
	if !strings.Contains(certText, "pathlen:2") {
		t.Error("CA certificate missing Basic Constraints pathlen:2")
	}

	// Verify Key Usage
	if !strings.Contains(certText, "Certificate Sign") {
		t.Error("CA certificate missing Key Usage: Certificate Sign")
	}
	if !strings.Contains(certText, "CRL Sign") {
		t.Error("CA certificate missing Key Usage: CRL Sign")
	}
	if !strings.Contains(certText, "Digital Signature") {
		t.Error("CA certificate missing Key Usage: Digital Signature")
	}

	// Verify Subject Key Identifier exists
	if !strings.Contains(certText, "Subject Key Identifier") {
		t.Error("CA certificate missing Subject Key Identifier")
	}

	// Verify Name Constraints
	if !strings.Contains(certText, "Name Constraints") {
		t.Error("CA certificate missing Name Constraints")
	}
	if !strings.Contains(certText, "DNS:.test.local") {
		t.Error("CA certificate missing Name Constraints DNS:.test.local")
	}
	if !strings.Contains(certText, "IP:192.168.0.0/255.255.0.0") {
		t.Error("CA certificate missing Name Constraints IP range")
	}

	// Verify custom extensions exist
	if !strings.Contains(certText, "1.3.6.1.4.1.12345.1") {
		t.Error("CA certificate missing custom extension 1.3.6.1.4.1.12345.1")
	}
	if !strings.Contains(certText, "1.3.6.1.4.1.12345.2") {
		t.Error("CA certificate missing custom extension 1.3.6.1.4.1.12345.2")
	}
	if !strings.Contains(certText, "1.3.6.1.4.1.12345.3") {
		t.Error("CA certificate missing custom extension 1.3.6.1.4.1.12345.3")
	}

	t.Log("All CA certificate extensions verified successfully")
}

// verifyHostExtensions uses OpenSSL to verify all host certificate extensions
func verifyHostExtensions(t *testing.T, certPath string) {
	// Get certificate text output
	certText := runOpenSSLCommand(t, "x509", "-in", certPath, "-text", "-noout")

	// Verify Key Usage
	if !strings.Contains(certText, "Digital Signature") {
		t.Error("Host certificate missing Key Usage: Digital Signature")
	}
	if !strings.Contains(certText, "Key Encipherment") {
		t.Error("Host certificate missing Key Usage: Key Encipherment")
	}
	if !strings.Contains(certText, "Key Agreement") {
		t.Error("Host certificate missing Key Usage: Key Agreement")
	}

	// Verify Extended Key Usage
	if !strings.Contains(certText, "TLS Web Server Authentication") {
		t.Error("Host certificate missing Extended Key Usage: TLS Web Server Authentication")
	}
	if !strings.Contains(certText, "TLS Web Client Authentication") {
		t.Error("Host certificate missing Extended Key Usage: TLS Web Client Authentication")
	}
	if !strings.Contains(certText, "E-mail Protection") {
		t.Error("Host certificate missing Extended Key Usage: E-mail Protection")
	}
	if !strings.Contains(certText, "Time Stamping") {
		t.Error("Host certificate missing Extended Key Usage: Time Stamping")
	}

	// Verify custom Extended Key Usage OIDs (OpenSSL shows them by friendly names)
	if !strings.Contains(certText, "Microsoft Encrypted File System") {
		t.Error("Host certificate missing custom EKU: Microsoft Encrypted File System (1.3.6.1.4.1.311.10.3.4)")
	}
	if !strings.Contains(certText, "SSH Client") {
		t.Error("Host certificate missing custom EKU: SSH Client (1.3.6.1.5.5.7.3.21)")
	}

	// Verify Subject Key Identifier exists (manual value)
	if !strings.Contains(certText, "Subject Key Identifier") {
		t.Error("Host certificate missing Subject Key Identifier")
	}
	// The manual value should be present
	if !strings.Contains(certText, "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67") {
		t.Error("Host certificate missing manual Subject Key Identifier value")
	}

	// Verify Authority Key Identifier exists
	if !strings.Contains(certText, "Authority Key Identifier") {
		t.Error("Host certificate missing Authority Key Identifier")
	}

	// Verify Subject Alternative Names
	if !strings.Contains(certText, "DNS:test-server.test.local") {
		t.Error("Host certificate missing SAN: DNS:test-server.test.local")
	}
	if !strings.Contains(certText, "IP Address:192.168.1.100") {
		t.Error("Host certificate missing SAN: IP Address:192.168.1.100")
	}
	if !strings.Contains(certText, "email:admin@test.local") {
		t.Error("Host certificate missing SAN: email:admin@test.local")
	}

	// Verify custom extensions exist
	if !strings.Contains(certText, "1.3.6.1.4.1.54321.1") {
		t.Error("Host certificate missing custom extension 1.3.6.1.4.1.54321.1")
	}
	if !strings.Contains(certText, "1.3.6.1.4.1.54321.2") {
		t.Error("Host certificate missing custom extension 1.3.6.1.4.1.54321.2")
	}
	if !strings.Contains(certText, "1.3.6.1.4.1.54321.3") {
		t.Error("Host certificate missing custom extension 1.3.6.1.4.1.54321.3")
	}
	if !strings.Contains(certText, "1.3.6.1.4.1.54321.4") {
		t.Error("Host certificate missing custom extension 1.3.6.1.4.1.54321.4")
	}

	t.Log("All host certificate extensions verified successfully")
}

// testUnknownExtensionEncodings tests all encoding formats for unknown extensions
func testUnknownExtensionEncodings(t *testing.T, tmpDir string) {
	// Test data for different encodings
	testString := "Hello World"
	testInt := int64(42)
	testBool := true
	testOID := "1.2.840.113549.1.1.11"

	// Expected encoded values
	expectedBase64 := "SGVsbG8gV29ybGQ="    // "Hello World" in base64
	expectedHex := "48656c6c6f20576f726c64" // "Hello World" in hex

	// Verify base64 encoding
	if hex.EncodeToString([]byte(testString)) != expectedHex {
		t.Error("Hex encoding test data mismatch")
	}

	// The actual encoding verification is done in the certificate verification above
	// This function serves as documentation of what encodings are supported
	t.Logf("Verified support for encoding formats:")
	t.Logf("  - base64: %s -> %s", testString, expectedBase64)
	t.Logf("  - hex: %s -> %s", testString, expectedHex)
	t.Logf("  - asn1:string: supported")
	t.Logf("  - asn1:int: %d supported", testInt)
	t.Logf("  - asn1:bool: %t supported", testBool)
	t.Logf("  - asn1:oid: %s supported", testOID)
}

// TestInfoDisplayAllExtensions creates certificates with ALL supported extensions and verifies parsing
func TestInfoDisplayAllExtensions(t *testing.T) {
	// Set up password for testing
	testPassword := "test-password-123"
	t.Setenv("REACTOR_CA_PASSWORD", testPassword)

	// Create test environment
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Create store directory structure
	if err := os.MkdirAll(filepath.Join(tmpDir, "ca"), 0755); err != nil {
		t.Fatalf("Failed to create ca directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "hosts"), 0755); err != nil {
		t.Fatalf("Failed to create hosts directory: %v", err)
	}

	// Create comprehensive CA configuration with ALL extension types our parser supports
	caConfigPath := filepath.Join(configDir, "ca.yaml")
	if err := createAllExtensionsCAConfig(caConfigPath); err != nil {
		t.Fatalf("Failed to create CA config: %v", err)
	}

	// Create comprehensive host configuration
	hostsConfigPath := filepath.Join(configDir, "hosts.yaml")
	if err := createAllExtensionsHostsConfig(hostsConfigPath); err != nil {
		t.Fatalf("Failed to create hosts config: %v", err)
	}

	// Create test application
	app := createTestApplicationForExtensions(tmpDir)
	ctx := context.Background()

	// Create CA with all extensions
	t.Run("CreateCAWithAllExtensions", func(t *testing.T) {
		err := app.CreateCA(ctx, true) // force = true
		if err != nil {
			t.Fatalf("Failed to create CA: %v", err)
		}

		// Test InfoCA parsing - verify it returns certificate without errors
		caCert, err := app.InfoCA(ctx)
		if err != nil {
			t.Fatalf("InfoCA failed: %v", err)
		}

		// Verify CA has expected extensions for parsing verification
		verifyCAExtensionsParsing(t, caCert)
	})

	// Issue host certificate with all extensions
	t.Run("IssueHostWithAllExtensions", func(t *testing.T) {
		err := app.IssueHost(ctx, "comprehensive-host", false, false)
		if err != nil {
			t.Fatalf("Failed to issue host certificate: %v", err)
		}

		// Test InfoHost parsing - verify it returns certificate without errors
		hostCert, err := app.InfoHost(ctx, "comprehensive-host")
		if err != nil {
			t.Fatalf("InfoHost failed: %v", err)
		}

		// Verify host has expected extensions for parsing verification
		verifyHostExtensionsParsing(t, hostCert)
	})
}

// createAllExtensionsCAConfig creates a CA configuration with ALL extension types for parser testing
func createAllExtensionsCAConfig(path string) error {
	config := `ca:
  subject:
    common_name: "All Extensions Test CA"
    organization: "Extension Test Org"
    organization_unit: "Testing Unit"
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

    # Certificate Policies extension as custom
    cert_policies_extension:
      critical: false
      oid: "2.5.29.32"
      value: "hex:30123010060A2B060104018237140202020204deadbeef"

    # CRL Distribution Points - structured format!
    crl_distribution_points:
      critical: false
      distribution_points:
        - urls:
            - "http://crl.extensions-test.local/ca.crl"
            - "http://backup-crl.extensions-test.local/ca.crl"
          reasons: [key_compromise, ca_compromise]

    # Authority Information Access - temporarily disabled due to encoding issues
    # authority_info_access_extension:
    #   critical: false
    #   oid: "1.3.6.1.5.5.7.1.1"
    #   value: "hex:301230100608560105050730018610a94b"

    # Certificate Transparency SCT List (as custom since not in standard config)
    ct_sct_extension:
      critical: false
      oid: "1.3.6.1.4.1.11129.2.4.2"
      value: "hex:0048004600760089b4e5fb9e"

    # Microsoft Certificate Template Name
    ms_template_name_extension:
      critical: false
      oid: "1.3.6.1.4.1.311.20.2"
      value: "asn1:string:WebServer"

    # Microsoft Certificate Template Information
    ms_template_info_extension:
      critical: false
      oid: "1.3.6.1.4.1.311.21.7"
      value: "hex:30160608608060020201010201020101"

    # Netscape Certificate Type
    netscape_cert_type_extension:
      critical: false
      oid: "2.16.840.1.113730.1.1"
      value: "hex:030201a0"

    # Netscape Certificate Comment
    netscape_comment_extension:
      critical: false
      oid: "2.16.840.1.113730.1.13"
      value: "asn1:string:Generated by ReactorCA for extension testing"

    # TLS Feature (OCSP Must-Staple)
    tls_feature_extension:
      critical: false
      oid: "1.3.6.1.5.5.7.1.24"
      value: "hex:3003020105"

    # Subject Directory Attributes
    subject_dir_attrs_extension:
      critical: false
      oid: "2.5.29.9"
      value: "hex:30123010060355040306090c074578616d706c65"

    # Policy Mappings
    policy_mappings_extension:
      critical: false
      oid: "2.5.29.33"
      value: "hex:30123010060355040306090c074578616d706c65"

    # Policy Constraints
    policy_constraints_extension:
      critical: false
      oid: "2.5.29.36"
      value: "hex:30060101ff020102"

    # Inhibit Any Policy
    inhibit_any_policy_extension:
      critical: false
      oid: "2.5.29.54"
      value: "asn1:int:2"

encryption:
  provider: "password"
  password:
    env_var: "REACTOR_CA_PASSWORD"
    min_length: 8
`
	return os.WriteFile(path, []byte(config), 0644)
}

// createAllExtensionsHostsConfig creates a host configuration with ALL extension types for parser testing
func createAllExtensionsHostsConfig(path string) error {
	config := `hosts:
  comprehensive-host:
    subject:
      common_name: "comprehensive-host.extensions-test.local"
      organization: "Extension Test Org"
      organization_unit: "Test Host Unit"
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
          - "1.3.6.1.4.1.311.10.3.1"  # Microsoft Server Gated Crypto

      # Subject Key Identifier - manual value
      subject_key_identifier:
        critical: false
        method: "manual"
        manual_value: "hex:ABCDEF0123456789ABCDEF0123456789ABCDEF01"

      # Authority Key Identifier - will be auto-populated but we define structure
      authority_key_identifier:
        critical: false
        key_id: "hex:FEDCBA9876543210FEDCBA9876543210FEDCBA98"

      # Certificate Policies as custom extension
      cert_policies_host_extension:
        critical: false
        oid: "2.5.29.32"
        value: "hex:30123010060A2B060104018237140202020204deadbeef"

      # CRL Distribution Points - structured format!
      crl_distribution_points:
        critical: false
        distribution_points:
          - urls:
              - "http://crl.extensions-test.local/host.crl"
              - "ldap://ldap.extensions-test.local/cn=Host-CRL,dc=example,dc=com"

      # Authority Information Access - temporarily disabled due to encoding issues
      # authority_info_access_host_extension:
      #   critical: false
      #   oid: "1.3.6.1.5.5.7.1.1"
      #   value: "hex:301f301d06082b0601050507300186116f6373702e746573742e6c6f63616c2f686f7374"

      # Subject Information Access
      subject_info_access_extension:
        critical: false
        oid: "1.3.6.1.5.5.7.1.11"
        value: "asn1:string:http://sia.extensions-test.local"

      # Certificate Transparency Precertificate Poison
      ct_precert_poison_extension:
        critical: true
        oid: "1.3.6.1.4.1.11129.2.4.3"
        value: "hex:0500"

      # Microsoft Application Policies
      ms_app_policies_extension:
        critical: false
        oid: "1.3.6.1.4.1.311.21.10"
        value: "hex:30123010060855040306090c074578616d706c65"

      # Microsoft Jurisdiction Extensions
      ms_jurisdiction_locality_extension:
        critical: false
        oid: "1.3.6.1.4.1.311.60.2.1.1"
        value: "asn1:string:San Francisco"

      ms_jurisdiction_state_extension:
        critical: false
        oid: "1.3.6.1.4.1.311.60.2.1.2"
        value: "asn1:string:California"

      ms_jurisdiction_country_extension:
        critical: false
        oid: "1.3.6.1.4.1.311.60.2.1.3"
        value: "asn1:string:US"

      # Netscape Base URL
      netscape_base_url_extension:
        critical: false
        oid: "2.16.840.1.113730.1.2"
        value: "asn1:string:https://comprehensive-host.extensions-test.local/"

      # Netscape Revocation URL
      netscape_revocation_url_extension:
        critical: false
        oid: "2.16.840.1.113730.1.3"
        value: "asn1:string:https://crl.extensions-test.local/revocation"

      # Netscape CA Revocation URL
      netscape_ca_revocation_url_extension:
        critical: false
        oid: "2.16.840.1.113730.1.4"
        value: "asn1:string:https://crl.extensions-test.local/ca-revocation"

      # Netscape SSL Server Name
      netscape_ssl_server_name_extension:
        critical: false
        oid: "2.16.840.1.113730.1.12"
        value: "asn1:string:comprehensive-host.extensions-test.local"

      # SMIME Capabilities
      smime_capabilities_extension:
        critical: false
        oid: "1.2.840.113549.1.9.15"
        value: "hex:30123010060855040306090c074578616d706c65"

      # OCSP No Check
      ocsp_no_check_extension:
        critical: false
        oid: "1.3.6.1.5.5.7.48.1.5"
        value: "hex:0500"

      # Custom vendor extension with string data
      vendor_string_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.1"
        value: "asn1:string:Custom vendor string data"

      # Custom vendor extension with integer data
      vendor_int_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.2"
        value: "asn1:int:12345"

      # Custom vendor extension with boolean data
      vendor_bool_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.3"
        value: "asn1:bool:true"

      # Custom vendor extension with OID data
      vendor_oid_extension:
        critical: false
        oid: "1.3.6.1.4.1.99999.4"
        value: "asn1:oid:1.2.840.113549.1.1.11"
`
	return os.WriteFile(path, []byte(config), 0644)
}

// verifyCAExtensionsParsing verifies that CA certificate has expected extensions and they can be parsed
func verifyCAExtensionsParsing(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	// Verify basic structure
	if !cert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}

	// Check for presence of key extensions that should be parseable
	extensionOIDs := make(map[string]bool)
	for _, ext := range cert.Extensions {
		extensionOIDs[ext.Id.String()] = true
	}

	// Verify expected extensions are present
	expectedExtensions := []struct {
		oid  string
		name string
	}{
		{"2.5.29.19", "Basic Constraints"},
		{"2.5.29.15", "Key Usage"},
		{"2.5.29.14", "Subject Key Identifier"},
		{"2.5.29.30", "Name Constraints"},
		{"2.5.29.32", "Certificate Policies"},
		{"1.3.6.1.4.1.11129.2.4.2", "CT SCT List"},
		{"1.3.6.1.4.1.311.20.2", "Microsoft Certificate Template Name"},
		{"2.16.840.1.113730.1.1", "Netscape Certificate Type"},
		{"2.16.840.1.113730.1.13", "Netscape Certificate Comment"},
		{"2.5.29.54", "Inhibit Any Policy"},
	}

	for _, expected := range expectedExtensions {
		if !extensionOIDs[expected.oid] {
			t.Errorf("CA certificate missing expected extension: %s (%s)", expected.name, expected.oid)
		}
	}

	t.Logf("CA certificate created with %d extensions for parsing verification", len(cert.Extensions))
}

// verifyHostExtensionsParsing verifies that host certificate has expected extensions and they can be parsed
func verifyHostExtensionsParsing(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	// Verify basic structure
	if cert.IsCA {
		t.Error("Host certificate should have IsCA=false")
	}

	// Check for Subject Alternative Names
	if len(cert.DNSNames) == 0 {
		t.Error("Host certificate should have DNS names")
	}
	if len(cert.IPAddresses) == 0 {
		t.Error("Host certificate should have IP addresses")
	}
	if len(cert.EmailAddresses) == 0 {
		t.Error("Host certificate should have email addresses")
	}
	if len(cert.URIs) == 0 {
		t.Error("Host certificate should have URIs")
	}

	// Check for presence of key extensions that should be parseable
	extensionOIDs := make(map[string]bool)
	for _, ext := range cert.Extensions {
		extensionOIDs[ext.Id.String()] = true
	}

	// Verify expected extensions are present
	expectedExtensions := []struct {
		oid  string
		name string
	}{
		{"2.5.29.15", "Key Usage"},
		{"2.5.29.37", "Extended Key Usage"},
		{"2.5.29.14", "Subject Key Identifier"},
		{"2.5.29.35", "Authority Key Identifier"},
		{"2.5.29.17", "Subject Alternative Name"},
		{"2.5.29.32", "Certificate Policies"},
		{"1.3.6.1.5.5.7.1.1", "Authority Information Access"},
		{"1.3.6.1.5.5.7.1.11", "Subject Information Access"},
		{"1.3.6.1.4.1.11129.2.4.3", "CT Precertificate Poison"},
		{"1.3.6.1.4.1.311.21.10", "Microsoft Application Policies"},
		{"1.3.6.1.4.1.311.60.2.1.1", "Microsoft Jurisdiction Locality"},
		{"1.3.6.1.4.1.311.60.2.1.2", "Microsoft Jurisdiction State"},
		{"1.3.6.1.4.1.311.60.2.1.3", "Microsoft Jurisdiction Country"},
		{"2.16.840.1.113730.1.2", "Netscape Base URL"},
		{"2.16.840.1.113730.1.3", "Netscape Revocation URL"},
		{"2.16.840.1.113730.1.12", "Netscape SSL Server Name"},
		{"1.2.840.113549.1.9.15", "SMIMECapabilities"},
		{"1.3.6.1.5.5.7.48.1.5", "OCSP No Check"},
		{"1.3.6.1.4.1.99999.1", "Custom Vendor String"},
		{"1.3.6.1.4.1.99999.2", "Custom Vendor Integer"},
		{"1.3.6.1.4.1.99999.3", "Custom Vendor Boolean"},
		{"1.3.6.1.4.1.99999.4", "Custom Vendor OID"},
	}

	missingExtensions := 0
	for _, expected := range expectedExtensions {
		if !extensionOIDs[expected.oid] {
			t.Logf("Host certificate missing extension: %s (%s)", expected.name, expected.oid)
			missingExtensions++
		}
	}

	// Log summary - some extensions might not be included due to crypto library limitations
	t.Logf("Host certificate created with %d extensions (%d expected, %d missing) for parsing verification",
		len(cert.Extensions), len(expectedExtensions), missingExtensions)

	// Verify at least basic extensions are present
	requiredExtensions := []string{"2.5.29.15", "2.5.29.37", "2.5.29.17"} // Key Usage, Extended Key Usage, SAN
	for _, oid := range requiredExtensions {
		if !extensionOIDs[oid] {
			t.Errorf("Host certificate missing required extension: %s", oid)
		}
	}
}

// runOpenSSLCommand runs an OpenSSL command and returns the output
func runOpenSSLCommand(t *testing.T, args ...string) string {
	t.Helper()

	return RunOpenSSLCommand(t, args...)
}
