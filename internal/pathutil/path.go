package pathutil

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandHomePath expands ~ to the user's home directory.
// Returns the original path if ~ expansion fails or if path doesn't start with ~/
func ExpandHomePath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to original path if we can't get home directory
		return path
	}

	return filepath.Join(homeDir, path[2:])
}

// ResolvePath handles both ~ expansion and relative path resolution.
// First expands ~ to user home directory if present, then resolves
// relative paths against basePath. Returns absolute paths unchanged.
func ResolvePath(path, basePath string) string {
	// First expand ~ if present
	expandedPath := ExpandHomePath(path)

	// If it's already absolute, return as-is
	if filepath.IsAbs(expandedPath) {
		return expandedPath
	}

	// Resolve relative path against basePath
	return filepath.Join(basePath, expandedPath)
}
