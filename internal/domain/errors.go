package domain

import "errors"

var (
	ErrCAAlreadyExists      = errors.New("CA already exists in the store")
	ErrCANotFound           = errors.New("CA not found in the store. Run 'ca create' first")
	ErrHostNotFoundInConfig = errors.New("host not found in hosts.yaml configuration")
	ErrHostNotFoundInStore  = errors.New("host certificate or key not found in store")
	ErrHostKeyNotFound      = errors.New("host key not found in store")
	ErrHostCertNotFound     = errors.New("host certificate not found in store")
	ErrKeyCertMismatch      = errors.New("private key does not match public key in certificate")
	ErrValidation           = errors.New("configuration validation failed")
	ErrActionAborted        = errors.New("action aborted by user")
	ErrNoDeployCommand      = errors.New("no deploy command configured for this host")
	ErrIncorrectPassword    = errors.New("incorrect password")
)

// ValidationWarning represents a non-fatal configuration issue.
type ValidationWarning struct {
	Type    string // "key_algorithm_mismatch", "hash_algorithm_mismatch", etc.
	Message string // Human-readable message for UI
	HostID  string // Optional: relevant host ID
}
