//go:build windows

package security

// DisableCoreDumps is a no-op on Windows as core dumps are not generated
// by default in the same way as Unix systems.
func DisableCoreDumps() error {
	// Windows doesn't generate core dumps by default, so this is a no-op
	return nil
}
