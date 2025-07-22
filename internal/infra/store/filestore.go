package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"reactor.dev/reactor-ca/internal/domain"
)

// FileStore implements the domain.Store interface using the local filesystem.
type FileStore struct {
	storePath string
	caPath    string
	hostsPath string
}

const (
	caCertFile   = "ca.crt"
	caKeyFile    = "ca.key.enc"
	hostCertFile = "cert.crt"
	hostKeyFile  = "cert.key.enc"
)

// NewFileStore creates a new filesystem-based store.
func NewFileStore(storePath string) *FileStore {
	return &FileStore{
		storePath: storePath,
		caPath:    filepath.Join(storePath, "ca"),
		hostsPath: filepath.Join(storePath, "hosts"),
	}
}

// Path getters
func (s *FileStore) GetHostCertPath(hostID string) string {
	return filepath.Join(s.hostsPath, hostID, hostCertFile)
}
func (s *FileStore) GetHostKeyPath(hostID string) string {
	return filepath.Join(s.hostsPath, hostID, hostKeyFile)
}
func (s *FileStore) GetCACertPath() string {
	return filepath.Join(s.caPath, caCertFile)
}

// CAExists checks if the CA certificate and key already exist.
func (s *FileStore) CAExists() (bool, error) {
	certPath := s.GetCACertPath()
	keyPath := filepath.Join(s.caPath, caKeyFile)

	certInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	keyInfo, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return certInfo != nil && keyInfo != nil, nil
}

// SaveCA saves the CA certificate and encrypted key to the store.
// If cert or key is nil, it's skipped.
func (s *FileStore) SaveCA(cert, encryptedKey []byte) error {
	if cert != nil {
		if err := os.WriteFile(s.GetCACertPath(), cert, 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate: %w", err)
		}
	}
	if encryptedKey != nil {
		if err := os.WriteFile(filepath.Join(s.caPath, caKeyFile), encryptedKey, 0600); err != nil {
			return fmt.Errorf("failed to write CA key: %w", err)
		}
	}
	return nil
}

// LoadCACert loads the CA public certificate from the store.
func (s *FileStore) LoadCACert() (*x509.Certificate, error) {
	pemData, err := os.ReadFile(s.GetCACertPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrCANotFound
		}
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from ca.crt")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCAKey loads the encrypted CA private key from the store.
func (s *FileStore) LoadCAKey() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.caPath, caKeyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrCANotFound
		}
		return nil, err
	}
	return data, nil
}

// HostExists checks if a directory for the host exists.
func (s *FileStore) HostExists(hostID string) (bool, error) {
	info, err := os.Stat(filepath.Join(s.hostsPath, hostID))
	if os.IsNotExist(err) {
		return false, nil
	}
	return info.IsDir(), err
}

// HostKeyExists checks if the host's private key exists.
func (s *FileStore) HostKeyExists(hostID string) (bool, error) {
	_, err := os.Stat(s.GetHostKeyPath(hostID))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// SaveHostCert saves a host's public certificate.
func (s *FileStore) SaveHostCert(hostID string, cert []byte) error {
	hostDir := filepath.Join(s.hostsPath, hostID)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.GetHostCertPath(hostID), cert, 0644)
}

// SaveHostKey saves a host's encrypted private key.
func (s *FileStore) SaveHostKey(hostID string, encryptedKey []byte) error {
	hostDir := filepath.Join(s.hostsPath, hostID)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.GetHostKeyPath(hostID), encryptedKey, 0600)
}

// LoadHostCert loads a host's public certificate.
func (s *FileStore) LoadHostCert(hostID string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(s.GetHostCertPath(hostID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrHostCertNotFound
		}
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from host cert %s", hostID)
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadHostKey loads a host's encrypted private key.
func (s *FileStore) LoadHostKey(hostID string) ([]byte, error) {
	data, err := os.ReadFile(s.GetHostKeyPath(hostID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrHostKeyNotFound
		}
		return nil, err
	}
	return data, nil
}

// ListHostIDs returns a slice of all host IDs (directory names) in the store.
func (s *FileStore) ListHostIDs() ([]string, error) {
	entries, err := os.ReadDir(s.hostsPath)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}

// DeleteHost removes a host's directory from the store.
func (s *FileStore) DeleteHost(hostID string) error {
	return os.RemoveAll(filepath.Join(s.hostsPath, hostID))
}

// GetAllEncryptedKeyPaths finds all *.key.enc files in the store.
func (s *FileStore) GetAllEncryptedKeyPaths() ([]string, error) {
	var paths []string

	// CA key
	caKeyPath := filepath.Join(s.caPath, caKeyFile)
	if _, err := os.Stat(caKeyPath); err == nil {
		paths = append(paths, caKeyPath)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Host keys
	hostIDs, err := s.ListHostIDs()
	if err != nil {
		return nil, err
	}
	for _, id := range hostIDs {
		hostKeyPath := s.GetHostKeyPath(id)
		if _, err := os.Stat(hostKeyPath); err == nil {
			paths = append(paths, hostKeyPath)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return paths, nil
}

// UpdateEncryptedKey writes new data to an existing key file path.
// It uses an atomic write-and-rename operation for safety.
func (s *FileStore) UpdateEncryptedKey(path string, data []byte) (err error) {
	// Create a temporary file in the same directory to ensure atomic rename.
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary key file: %w", err)
	}
	// Ensure the temp file is removed on error
	defer func() {
		if err != nil {
			os.Remove(tmpFile.Name())
		}
	}()

	if err = os.Chmod(tmpFile.Name(), 0600); err != nil {
		return fmt.Errorf("failed to set permissions on temporary key file: %w", err)
	}

	if _, err = tmpFile.Write(data); err != nil {
		_ = tmpFile.Close() // Close file before trying to remove.
		return fmt.Errorf("failed to write to temporary key file: %w", err)
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary key file: %w", err)
	}

	// Atomically replace the old file with the new one.
	err = os.Rename(tmpFile.Name(), path)
	if err != nil {
		return fmt.Errorf("failed to rename temporary key file to final destination: %w", err)
	}

	return nil
}
