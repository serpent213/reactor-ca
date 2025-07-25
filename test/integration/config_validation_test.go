//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/infra/config"
	"reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/exec"
	"reactor.de/reactor-ca/internal/infra/identity"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/infra/store"
)

func TestValidateAllExampleConfigs(t *testing.T) {
	// Get the project root directory
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}

	exampleConfigDir := filepath.Join(projectRoot, "example_config")
	
	// Get all YAML files from example_config directory
	exampleFiles, err := filepath.Glob(filepath.Join(exampleConfigDir, "*.yaml"))
	if err != nil {
		t.Fatalf("Failed to list example config files: %v", err)
	}

	if len(exampleFiles) == 0 {
		t.Fatal("No example config files found")
	}

	// Test each example configuration
	for _, exampleFile := range exampleFiles {
		t.Run(filepath.Base(exampleFile), func(t *testing.T) {
			testValidateExampleConfig(t, exampleFile)
		})
	}
}

func testValidateExampleConfig(t *testing.T, exampleFilePath string) {
	// Create temporary directory for this test
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Copy the appropriate configuration files based on the example file
	exampleFileName := filepath.Base(exampleFilePath)
	
	var err error
	if exampleFileName == "hosts.yaml" || (filepath.Ext(exampleFileName) == ".yaml" && len(exampleFileName) >= 5 && exampleFileName[:5] == "hosts") {
		// For hosts*.yaml, create minimal ca.yaml and copy the hosts file
		if err = createMinimalCAConfig(filepath.Join(configDir, "ca.yaml")); err != nil {
			t.Fatalf("Failed to create minimal ca.yaml: %v", err)
		}
		if err = copyFile(exampleFilePath, filepath.Join(configDir, "hosts.yaml")); err != nil {
			t.Fatalf("Failed to copy hosts.yaml: %v", err)
		}
	} else {
		// For ca*.yaml variants, copy as ca.yaml and create minimal hosts.yaml
		if err = copyFile(exampleFilePath, filepath.Join(configDir, "ca.yaml")); err != nil {
			t.Fatalf("Failed to copy ca config: %v", err)
		}
		if err = createMinimalHostsConfig(filepath.Join(configDir, "hosts.yaml")); err != nil {
			t.Fatalf("Failed to create minimal hosts.yaml: %v", err)
		}
	}

	// Create Application instance with the temporary config
	app := createTestApplication(tmpDir)

	// Validate the configuration
	ctx := context.Background()
	err = app.ValidateConfig(ctx)
	if err != nil {
		t.Fatalf("Validation failed for %s: %v", exampleFileName, err)
	}
}

func createTestApplication(rootPath string) *app.Application {
	logger := &mockLogger{}
	configLoader := config.NewYAMLConfigLoader(filepath.Join(rootPath, "config"))
	store := store.NewFileStore(rootPath)
	passwordProvider := password.NewProvider()
	commander := exec.NewCommander()
	identityProviderFactory := identity.NewFactory()
	cryptoServiceFactory := crypto.NewServiceFactory()
	validationService := crypto.NewValidationService()

	return app.NewApplication(
		rootPath,
		logger,
		configLoader,
		store,
		nil, // cryptoSvc not needed for config validation
		passwordProvider,
		nil, // userInteraction not needed for config validation
		commander,
		nil, // identityProvider not needed for config validation
		identityProviderFactory,
		cryptoServiceFactory,
		validationService,
	)
}

type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...interface{})  {}
func (m *mockLogger) Error(msg string, args ...interface{}) {}
func (m *mockLogger) Log(msg string)                        {}

func findProjectRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up the directory tree looking for go.mod
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}
	
	return "", os.ErrNotExist
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	
	return os.WriteFile(dst, data, 0644)
}

func createMinimalCAConfig(path string) error {
	minimalCA := `ca:
  subject:
    common_name: "Test CA"
    organization: "Test Org"
    country: "US"
  validity:
    years: 1
  key_algorithm: "ec256"
  hash_algorithm: "sha256"

encryption:
  provider: "password"
`
	return os.WriteFile(path, []byte(minimalCA), 0644)
}

func createMinimalHostsConfig(path string) error {
	minimalHosts := `hosts: {}
`
	return os.WriteFile(path, []byte(minimalHosts), 0644)
}