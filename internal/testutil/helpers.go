package testutil

import (
	"os"
	"testing"
)

// WithSilentOutput captures stdout and stderr during test execution to eliminate UI noise.
// This helper redirects output to prevent debug messages from cluttering test output
// while preserving all test functionality.
func WithSilentOutput(t *testing.T, fn func()) {
	t.Helper()

	// Save original stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	// Create pipes to capture output
	_, wOut, _ := os.Pipe()
	_, wErr, _ := os.Pipe()

	// Redirect stdout and stderr to /dev/null equivalent
	os.Stdout = wOut
	os.Stderr = wErr

	// Ensure we restore stdout/stderr even if test panics
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		wOut.Close()
		wErr.Close()
	}()

	// Run the test function
	fn()
}
