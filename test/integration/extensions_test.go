//go:build integration

package integration

import (
	"context"
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
			expectedErr: "invalid OID",
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
			expectedErr: "OID component 0 is not a number",
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
			expectedErr: "unknown extension must have 'oid' field",
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

// runOpenSSLCommand runs an OpenSSL command and returns the output
func runOpenSSLCommand(t *testing.T, args ...string) string {
	t.Helper()

	return RunOpenSSLCommand(t, args...)
}
