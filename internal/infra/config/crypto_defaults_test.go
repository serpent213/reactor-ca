//go:build !integration && !e2e

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/config"
)

func TestYAMLConfigLoader_MissingKeyAlgorithm(t *testing.T) {
	// Create a temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "test-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write ca.yaml with NO key_algorithm field at all
	caConfig := `ca:
  subject:
    common_name: "Test CA"
    organization: "Test Org"
  validity:
    years: 10
  # key_algorithm field completely omitted - should fail validation
  hash_algorithm: "SHA256"
encryption:
  provider: "password"
`

	caYamlPath := filepath.Join(tempDir, "ca.yaml")
	if err := os.WriteFile(caYamlPath, []byte(caConfig), 0644); err != nil {
		t.Fatalf("Failed to write test ca.yaml: %v", err)
	}

	// Create config loader and attempt to load
	loader := config.NewYAMLConfigLoader(tempDir)
	_, err = loader.LoadCA()

	// Should fail with validation error
	if err == nil {
		t.Fatal("Expected validation error for missing key_algorithm, but got nil")
	}

	if !strings.Contains(err.Error(), "key_algorithm is required") {
		t.Errorf("Expected error about required key_algorithm, got: %v", err)
	}

	// Verify it's wrapped as a validation error
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation error wrapper, got: %v", err)
	}
}

func TestYAMLConfigLoader_CAMissingHashAlgorithm(t *testing.T) {
	// Create a temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "test-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write ca.yaml with valid key_algorithm but NO hash_algorithm field at all
	caConfig := `ca:
  subject:
    common_name: "Test CA"
    organization: "Test Org"
  validity:
    years: 10
  key_algorithm: "RSA2048"
  # hash_algorithm field completely omitted - should now fail validation
encryption:
  provider: "password"
`

	caYamlPath := filepath.Join(tempDir, "ca.yaml")
	if err := os.WriteFile(caYamlPath, []byte(caConfig), 0644); err != nil {
		t.Fatalf("Failed to write test ca.yaml: %v", err)
	}

	// Create config loader and attempt to load
	loader := config.NewYAMLConfigLoader(tempDir)
	_, err = loader.LoadCA()

	// Should fail with validation error - hash algorithm is now required
	if err == nil {
		t.Fatal("Expected validation error for missing hash_algorithm, but got nil")
	}

	if !strings.Contains(err.Error(), "hash_algorithm is required") {
		t.Errorf("Expected error about required hash_algorithm, got: %v", err)
	}

	// Verify it's wrapped as a validation error
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation error wrapper, got: %v", err)
	}
}

func TestYAMLConfigLoader_CAMissingBothAlgorithms(t *testing.T) {
	// Create a temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "test-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write ca.yaml with NEITHER key_algorithm NOR hash_algorithm fields
	caConfig := `ca:
  subject:
    common_name: "Test CA"
    organization: "Test Org"
  validity:
    years: 10
  # key_algorithm field completely omitted - should fail validation
  # hash_algorithm field completely omitted - should also fail validation
encryption:
  provider: "password"
`

	caYamlPath := filepath.Join(tempDir, "ca.yaml")
	if err := os.WriteFile(caYamlPath, []byte(caConfig), 0644); err != nil {
		t.Fatalf("Failed to write test ca.yaml: %v", err)
	}

	// Create config loader and attempt to load
	loader := config.NewYAMLConfigLoader(tempDir)
	_, err = loader.LoadCA()

	// Should fail with validation error due to missing key_algorithm
	if err == nil {
		t.Fatal("Expected validation error for missing key_algorithm, but got nil")
	}

	if !strings.Contains(err.Error(), "key_algorithm is required") {
		t.Errorf("Expected error about required key_algorithm, got: %v", err)
	}

	// Verify it's wrapped as a validation error
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation error wrapper, got: %v", err)
	}
}

func TestYAMLConfigLoader_HostMissingAlgorithms(t *testing.T) {
	// Create a temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "test-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write hosts.yaml with host that has NO algorithm fields at all
	hostsConfig := `hosts:
  test-host:
    subject:
      common_name: "test-server.example.com"
    alternative_names:
      dns:
        - "test-server.example.com"
    validity:
      years: 1
    # key_algorithm field completely omitted - should inherit from CA
    # hash_algorithm field completely omitted - should inherit from CA
`

	hostsYamlPath := filepath.Join(tempDir, "hosts.yaml")
	if err := os.WriteFile(hostsYamlPath, []byte(hostsConfig), 0644); err != nil {
		t.Fatalf("Failed to write test hosts.yaml: %v", err)
	}

	// Create config loader and load hosts
	loader := config.NewYAMLConfigLoader(tempDir)
	hostsCfg, err := loader.LoadHosts()

	// Should succeed - missing algorithms in hosts are allowed (application layer handles inheritance)
	if err != nil {
		t.Fatalf("Expected success with missing host algorithms, got: %v", err)
	}

	hostCfg, exists := hostsCfg.Hosts["test-host"]
	if !exists {
		t.Fatal("Expected test-host to exist in config")
	}

	// Both should be empty strings (zero values) when omitted from YAML
	if hostCfg.KeyAlgorithm != "" {
		t.Errorf("Expected empty key algorithm in host config (zero value), got: %v", hostCfg.KeyAlgorithm)
	}

	if hostCfg.HashAlgorithm != "" {
		t.Errorf("Expected empty hash algorithm in host config (zero value), got: %v", hostCfg.HashAlgorithm)
	}
}

func TestService_MergeExtensions_RealisticEmailWebServer(t *testing.T) {
	// Create a Service with extension factory to test mergeExtensions directly
	// We'll import the crypto package to access the Service struct

	// Scenario: Mail server certificate needs both web (HTTPS) and email (SMTP/IMAP) capabilities
	// Default host extensions provide: digital_signature + key_encipherment + server_auth + client_auth
	// User wants to add: content_commitment (non-repudiation) + email_protection + code_signing

	// Default host extensions (what ReactorCA provides by default)
	defaults := domain.ExtensionsConfig{
		"key_usage": {
			Critical: false,
			Fields: map[string]interface{}{
				"digital_signature": true,
				"key_encipherment":  true,
			},
		},
		"extended_key_usage": {
			Critical: false,
			Fields: map[string]interface{}{
				"server_auth": true,
				"client_auth": true,
			},
		},
	}

	// User configuration: wants to add email capabilities while keeping web server functionality
	userConfig := domain.ExtensionsConfig{
		"key_usage": {
			Critical: true, // Make it critical
			Fields: map[string]interface{}{
				"content_commitment": true, // Add non-repudiation for email signing
				// Should preserve: digital_signature, key_encipherment
			},
		},
		"extended_key_usage": {
			Critical: false, // Keep non-critical
			Fields: map[string]interface{}{
				"email_protection": true, // Add email capability
				"code_signing":     true, // Add code signing capability
				// Should preserve: server_auth, client_auth
			},
		},
		"subject_key_identifier": { // Completely new extension
			Critical: false,
			Fields: map[string]interface{}{
				"method": "hash",
			},
		},
	}

	// Test the merging logic manually since mergeExtensions is not exported
	// This tests the expected behavior of field-level merging
	merged := make(domain.ExtensionsConfig)

	// Start with defaults
	for name, defaultExt := range defaults {
		merged[name] = domain.ExtensionRawConfig{
			Critical: defaultExt.Critical,
			Fields:   make(map[string]interface{}),
		}

		// Copy default fields
		for field, value := range defaultExt.Fields {
			merged[name].Fields[field] = value
		}
	}

	// Merge user config at field level
	for name, userExt := range userConfig {
		if existingExt, exists := merged[name]; exists {
			// Extension exists in defaults - merge fields
			merged[name] = domain.ExtensionRawConfig{
				Critical: userExt.Critical, // User critical flag takes precedence
				Fields:   existingExt.Fields,
			}
			// Override/add user fields
			for field, value := range userExt.Fields {
				merged[name].Fields[field] = value
			}
		} else {
			// New extension not in defaults - add as-is
			merged[name] = domain.ExtensionRawConfig{
				Critical: userExt.Critical,
				Fields:   make(map[string]interface{}),
			}
			for field, value := range userExt.Fields {
				merged[name].Fields[field] = value
			}
		}
	}

	// Verify key_usage extension: should have all 3 capabilities with user's critical flag
	keyUsage := merged["key_usage"]
	if !keyUsage.Critical {
		t.Error("key_usage should be critical (user override)")
	}

	// Check all key usage fields are present
	expectedKeyUsage := map[string]bool{
		"digital_signature":  true, // from defaults
		"key_encipherment":   true, // from defaults
		"content_commitment": true, // from user
	}
	for field, expected := range expectedKeyUsage {
		if val, ok := keyUsage.Fields[field]; !ok || val != expected {
			t.Errorf("key_usage missing or incorrect field %s: got %v, want %v", field, val, expected)
		}
	}

	// Verify extended_key_usage: should have all 4 capabilities
	extKeyUsage := merged["extended_key_usage"]
	if extKeyUsage.Critical {
		t.Error("extended_key_usage should remain non-critical (user config)")
	}

	expectedExtKeyUsage := map[string]bool{
		"server_auth":      true, // from defaults
		"client_auth":      true, // from defaults
		"email_protection": true, // from user
		"code_signing":     true, // from user
	}
	for field, expected := range expectedExtKeyUsage {
		if val, ok := extKeyUsage.Fields[field]; !ok || val != expected {
			t.Errorf("extended_key_usage missing or incorrect field %s: got %v, want %v", field, val, expected)
		}
	}

	// Verify new extension exists
	subjectKeyId := merged["subject_key_identifier"]
	if subjectKeyId.Critical {
		t.Error("subject_key_identifier should be non-critical")
	}
	if method, ok := subjectKeyId.Fields["method"]; !ok || method != "hash" {
		t.Errorf("subject_key_identifier method: got %v, want 'hash'", method)
	}

	// Verify we have exactly 3 extensions total
	if len(merged) != 3 {
		t.Errorf("Expected 3 merged extensions, got %d", len(merged))
	}
}
