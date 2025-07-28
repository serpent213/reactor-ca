//go:build !integration && !e2e

package ui

import (
	"strings"
	"testing"
)

func TestFormatHostStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		contains []string // Check that result contains these strings
	}{
		{
			name:     "issued status",
			status:   "issued",
			contains: []string{"ISSUED", "✓"},
		},
		{
			name:     "configured status",
			status:   "configured",
			contains: []string{"CONFIGURED", "○"},
		},
		{
			name:     "orphaned status",
			status:   "orphaned",
			contains: []string{"ORPHANED", "!"},
		},
		{
			name:     "unknown status",
			status:   "invalid-status",
			contains: []string{"UNKNOWN"},
		},
		{
			name:     "empty status",
			status:   "",
			contains: []string{"UNKNOWN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatHostStatus(tt.status)

			// Check that result contains expected strings
			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("FormatHostStatus(%q) = %q, expected to contain %q", tt.status, result, expected)
				}
			}

			// Verify result is not empty
			if result == "" {
				t.Errorf("FormatHostStatus(%q) returned empty string", tt.status)
			}
		})
	}
}

func TestPrintBlock(t *testing.T) {
	// Since PrintBlock outputs to stdout, we'll capture it
	// This is a simple function that just calls fmt.Println

	// Test cases that don't require output capture for basic coverage
	testCases := []string{
		"Hello, World!",
		"Multi-line\ntext block",
		"",
		"   spaces   ",
	}

	// Just call the function - it should not panic
	for _, testCase := range testCases {
		t.Run("print_"+testCase, func(t *testing.T) {
			// This will print to stdout but won't cause test failure
			PrintBlock(testCase)
			// If we reach here, the function didn't panic
		})
	}
}

func TestNewHostsTable(t *testing.T) {
	// Test that NewHostsTable creates a table without panicking
	table := NewHostsTable()

	if table == nil {
		t.Error("NewHostsTable() returned nil")
		return
	}

	// Test that we can set headers and data
	table.Header([]string{"Host", "Status", "Expires"})
	table.Append([]string{"web-server", "ISSUED", "2024-12-31"})

	// The function should complete without errors
	// (We're not checking output formatting, just that it works)
}
