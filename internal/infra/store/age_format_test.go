//go:build !integration && !e2e

package store

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAgeKeyFile(t *testing.T) {
	tempDir := t.TempDir()

	store := &FileStore{
		hostsPath: filepath.Join(tempDir, "hosts"),
	}

	// Create host directory
	hostID := "test-host"
	hostDir := filepath.Join(store.hostsPath, hostID)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatalf("Failed to create host directory: %v", err)
	}

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "valid age file with single stanza",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8
binary payload goes here`,
			expected: true,
		},
		{
			name: "valid age file with multiple stanzas",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA A5qWRWJZkpor8OBdp1JLlFjQP6syoRs+e6PXcFla6gbu
Dvp/W/M8dCwnQr2VLnr0i6G7SmDYmVmQeyiJhXOjT54
-> ssh-ed25519 cOETAA s6Upb2yvt1lW0Zn6UTFbH68mR/755UOwXB3yraNGRzQ
YSX6YYyhSpLEa0RRaeLICpbHXcdBSjf3gtz0DPIp4e4
--- zc5lBtQEqmGmp4WTNAG8TpSQd0ZcY3De0LhltFfnXB4
binary payload goes here`,
			expected: true,
		},
		{
			name: "missing intro line",
			content: `-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8
binary payload`,
			expected: false,
		},
		{
			name: "wrong intro line",
			content: `age-encryption.org/v2
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8
binary payload`,
			expected: false,
		},
		{
			name: "missing footer",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
binary payload without footer`,
			expected: false,
		},
		{
			name: "invalid footer format - missing dashes",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8
binary payload`,
			expected: false,
		},
		{
			name: "invalid footer format - wrong number of parts",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8 extra
binary payload`,
			expected: false,
		},
		{
			name: "invalid MAC - not base64",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- invalid-base64-@#$%
binary payload`,
			expected: false,
		},
		{
			name: "invalid MAC - wrong length (too short)",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- ` + base64.StdEncoding.EncodeToString([]byte("tooshort")) + `
binary payload`,
			expected: false,
		},
		{
			name: "invalid MAC - wrong length (too long)",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- ` + base64.StdEncoding.EncodeToString([]byte("this MAC is way too long to be valid for age format")) + `
binary payload`,
			expected: false,
		},
		{
			name: "valid MAC - exactly 32 bytes",
			content: `age-encryption.org/v1
-> piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- ` + base64.RawStdEncoding.EncodeToString([]byte("this is exactly 32 bytes long!!!")) + `
binary payload`,
			expected: true,
		},
		{
			name: "invalid stanza - doesn't start with ->",
			content: `age-encryption.org/v1
piv-p256 0B8FFA AsTxbWgK8HSaltf19EPVhkjykNiM4GP6kMCvV+QvmIBb
a919gj3tJ55rsvSy6kgU1X43o2/6WUAyRXRMp94PdLU
--- qyBkIB8rEZXLTXqRjkzrVFciFPpAPeJVScClfz/YMT8
binary payload`,
			expected: false,
		},
		{
			name:     "empty file",
			content:  "",
			expected: false,
		},
		{
			name:     "only intro line",
			content:  "age-encryption.org/v1\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test content to the host key file
			keyPath := store.GetHostKeyPath(hostID)
			if err := os.WriteFile(keyPath, []byte(tt.content), 0600); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			result := store.ValidateAgeKeyFile(hostID)
			if result != tt.expected {
				t.Errorf("ValidateAgeKeyFile() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateAgeKeyFile_FileSystemErrors(t *testing.T) {
	tempDir := t.TempDir()

	store := &FileStore{
		hostsPath: filepath.Join(tempDir, "hosts"),
	}

	tests := []struct {
		name     string
		hostID   string
		setup    func() error
		expected bool
	}{
		{
			name:     "file does not exist",
			hostID:   "nonexistent",
			setup:    func() error { return nil },
			expected: false,
		},
		{
			name:   "directory instead of file",
			hostID: "dir-host",
			setup: func() error {
				keyPath := store.GetHostKeyPath("dir-host")
				return os.MkdirAll(keyPath, 0755)
			},
			expected: false,
		},
		{
			name:   "unreadable file (no permissions)",
			hostID: "no-perms",
			setup: func() error {
				hostDir := filepath.Join(store.hostsPath, "no-perms")
				if err := os.MkdirAll(hostDir, 0755); err != nil {
					return err
				}
				keyPath := store.GetHostKeyPath("no-perms")
				if err := os.WriteFile(keyPath, []byte("test"), 0000); err != nil {
					return err
				}
				return nil
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.setup(); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			result := store.ValidateAgeKeyFile(tt.hostID)
			if result != tt.expected {
				t.Errorf("ValidateAgeKeyFile() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateAgeHeader_Direct(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "minimal valid age format",
			content: `age-encryption.org/v1
-> test-stanza base64data
c2hvcnQ
--- ` + base64.RawStdEncoding.EncodeToString([]byte("this is exactly 32 bytes long!!!")) + `
`,
			expected: true,
		},
		{
			name: "truncated file during stanza reading",
			content: `age-encryption.org/v1
-> incomplete`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.content)
			err := validateAgeHeader(reader)
			result := err == nil
			if result != tt.expected {
				t.Errorf("validateAgeHeader() error = %v, expected success = %v", err, tt.expected)
			}
		})
	}
}
