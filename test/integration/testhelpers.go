//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
)

// MockLogger provides a no-op logger for integration testing
type MockLogger struct{}

func (m *MockLogger) Info(msg string, args ...interface{})    {}
func (m *MockLogger) Error(msg string, args ...interface{})   {}
func (m *MockLogger) Warning(msg string, args ...interface{}) {}
func (m *MockLogger) Log(msg string)                          {}

// mockUserInteraction for testing user confirmation prompts
type mockUserInteraction struct {
	confirmResponse bool
}

func (m *mockUserInteraction) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, nil
}

// RunOpenSSLCommand runs an OpenSSL command and returns the output
// This is a shared helper for integration tests that need to verify certificate contents
func RunOpenSSLCommand(t *testing.T, args ...string) string {
	t.Helper()

	// Check if OpenSSL is available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("OpenSSL not available in PATH: %v", err)
	}

	// Prepend "openssl" to the arguments
	fullArgs := append([]string{"openssl"}, args...)

	// Run the command
	cmd := exec.Command(fullArgs[0], fullArgs[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL command failed: %s\nCommand: %s\nOutput: %s",
			err, strings.Join(fullArgs, " "), string(output))
	}

	return string(output)
}

// VerifyOpenSSLVersion checks if OpenSSL version is compatible with our tests
func VerifyOpenSSLVersion(t *testing.T) {
	t.Helper()

	output := RunOpenSSLCommand(t, "version")
	t.Logf("OpenSSL version: %s", strings.TrimSpace(output))

	// Basic check - should contain "OpenSSL"
	if !strings.Contains(output, "OpenSSL") {
		t.Skipf("Unexpected OpenSSL version output: %s", output)
	}
}
