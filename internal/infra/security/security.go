//go:build !windows

package security

import "syscall"

// DisableCoreDumps prevents the application from generating core dumps,
// which is critical for security as core dumps could expose sensitive
// cryptographic material such as private keys and passwords.
func DisableCoreDumps() error {
	var limit syscall.Rlimit
	limit.Cur = 0 // Set current limit to 0
	limit.Max = 0 // Set maximum limit to 0
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &limit)
}
