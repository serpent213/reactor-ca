package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomePath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Could not get home directory: %v", err)
	}

	// Get a cross-platform absolute path for testing
	absPath, err := filepath.Abs("test_absolute_path")
	if err != nil {
		t.Fatalf("Could not create absolute path: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "expand tilde path",
			input:    "~/test/path",
			expected: filepath.Join(homeDir, "test/path"),
		},
		{
			name:     "absolute path unchanged",
			input:    absPath,
			expected: absPath,
		},
		{
			name:     "relative path unchanged",
			input:    "relative/path",
			expected: "relative/path",
		},
		{
			name:     "tilde only",
			input:    "~",
			expected: "~",
		},
		{
			name:     "tilde without slash",
			input:    "~test",
			expected: "~test",
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandHomePath(tt.input)
			if result != tt.expected {
				t.Errorf("ExpandHomePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Could not get home directory: %v", err)
	}

	// Create cross-platform absolute paths for testing
	basePath, err := filepath.Abs("base/path")
	if err != nil {
		t.Fatalf("Could not create base path: %v", err)
	}
	absTestPath, err := filepath.Abs("absolute/path")
	if err != nil {
		t.Fatalf("Could not create absolute test path: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		basePath string
		expected string
	}{
		{
			name:     "absolute path unchanged",
			path:     absTestPath,
			basePath: basePath,
			expected: absTestPath,
		},
		{
			name:     "relative path resolved",
			path:     "relative/path",
			basePath: basePath,
			expected: filepath.Join(basePath, "relative/path"),
		},
		{
			name:     "tilde path expanded and absolute",
			path:     "~/config/app",
			basePath: basePath,
			expected: filepath.Join(homeDir, "config/app"),
		},
		{
			name:     "empty path resolved to base",
			path:     "",
			basePath: basePath,
			expected: basePath,
		},
		{
			name:     "dot path resolved",
			path:     "./config",
			basePath: basePath,
			expected: filepath.Join(basePath, "config"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolvePath(tt.path, tt.basePath)
			// Normalize paths for comparison on different OS
			result = filepath.Clean(result)
			expected := filepath.Clean(tt.expected)

			if result != expected {
				t.Errorf("ResolvePath(%q, %q) = %q, want %q", tt.path, tt.basePath, result, expected)
			}
		})
	}
}

func TestExpandHomePathFallback(t *testing.T) {
	// Test fallback behavior when home directory can't be determined
	// This is hard to test directly, but we can test the expected behavior

	// Test with a path that should be expanded
	input := "~/test/path"
	result := ExpandHomePath(input)

	// Result should either be expanded (if home dir available) or unchanged (fallback)
	if !filepath.IsAbs(result) && result != input {
		t.Errorf("ExpandHomePath fallback behavior incorrect: got %q", result)
	}
}
