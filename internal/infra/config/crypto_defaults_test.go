//go:build !integration && !e2e

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
