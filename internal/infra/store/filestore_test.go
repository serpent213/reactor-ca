//go:build !integration && !e2e

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore_HostExists(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	store := &FileStore{
		hostsPath: filepath.Join(tempDir, "hosts"),
	}

	tests := []struct {
		name     string
		hostID   string
		setup    func() error
		expected bool
		wantErr  bool
	}{
		{
			name:   "host directory exists",
			hostID: "web-server",
			setup: func() error {
				return os.MkdirAll(filepath.Join(store.hostsPath, "web-server"), 0755)
			},
			expected: true,
			wantErr:  false,
		},
		{
			name:     "host directory does not exist",
			hostID:   "nonexistent",
			setup:    func() error { return nil },
			expected: false,
			wantErr:  false,
		},
		{
			name:   "file exists instead of directory",
			hostID: "file-not-dir",
			setup: func() error {
				if err := os.MkdirAll(store.hostsPath, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(store.hostsPath, "file-not-dir"), []byte("test"), 0644)
			},
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			if err := tt.setup(); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			result, err := store.HostExists(tt.hostID)

			if tt.wantErr {
				if err == nil {
					t.Error("HostExists() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("HostExists() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("HostExists() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
