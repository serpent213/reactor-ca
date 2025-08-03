//go:build !integration && !e2e

package ui

import (
	"testing"
)

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
