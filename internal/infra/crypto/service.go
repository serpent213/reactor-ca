package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"reactor.dev/reactor-ca/internal/domain"
	"reactor.dev/reactor-ca/internal/infra/crypto/pkcs8"
)

// Service implements the domain.CryptoService interface.
type Service struct{}

// NewService creates a new crypto service.
func NewService() *Service {
	return &Service{}
}

// GeneratePrivateKey generates a new private key based on the specified algorithm.
func (s *Service) GeneratePrivateKey(algo domain.KeyAlgorithm) (crypto.Signer, error) {
	switch algo {
	case domain.RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case domain.RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case domain.RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case domain.ECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case domain.ECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case domain.ECP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case domain.ED25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// CreateRootCertificate creates a new self-signed CA certificate.
func (s *Service) CreateRootCertificate(cfg *domain.CAConfig, key crypto.Signer) (*x509.Certificate, error) {
	template, err := s.createBaseTemplate(&cfg.CA.Subject, cfg.CA.Validity)
	if err != nil {
		return nil, err
	}

	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.BasicConstraintsValid = true

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// CreateHostCertificate creates a new host certificate signed by the CA.
func (s *Service) CreateHostCertificate(hostCfg *domain.HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error) {
	template, err := s.createBaseTemplate(&hostCfg.Subject, hostCfg.Validity)
	if err != nil {
		return nil, err
	}

	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	template.DNSNames = append(template.DNSNames, hostCfg.AlternativeNames.DNS...)
	for _, ipStr := range hostCfg.AlternativeNames.IP {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	template.EmailAddresses = append(template.EmailAddresses, hostCfg.AlternativeNames.Email...)
	for _, uriStr := range hostCfg.AlternativeNames.URI {
		if uri, err := url.Parse(uriStr); err == nil {
			template.URIs = append(template.URIs, uri)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, hostPublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// SignCSR signs an external CSR with the CA key.
func (s *Service) SignCSR(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer, validityDays int) (*x509.Certificate, error) {
	serialNumber, err := s.newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(0, 0, validityDays).UTC(),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}
	return x509.ParseCertificate(derBytes)
}

// EncryptPrivateKey encrypts a private key using PKCS#8 and AES-256-GCM with PBKDF2.
func (s *Service) EncryptPrivateKey(key crypto.Signer, password []byte) ([]byte, error) {
	// Using AES-256-GCM as it's a modern, authenticated encryption cipher.
	// Bumping KDF parameters for future-proofing.
	opts := pkcs8.Opts{
		Cipher: pkcs8.AES256GCM,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize: 16,
			// Increased iterations for better brute-force resistance.
			IterationCount: 600000,
			// Using SHA-256 for the KDF's HMAC (well supported by youmark/pkcs8).
			HMACHash: crypto.SHA256,
		},
	}

	encryptedDER, err := pkcs8.MarshalPrivateKey(key, password, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedDER,
	}), nil
}

// DecryptPrivateKey decrypts a PEM-encoded private key.
func (s *Service) DecryptPrivateKey(pemData, password []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
	if err != nil {
		// Check for incorrect password error from youmark/pkcs8 library
		if err.Error() == "pkcs8: incorrect password" {
			return nil, domain.ErrIncorrectPassword
		}
		return nil, fmt.Errorf("failed to parse/decrypt private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a crypto.Signer")
	}
	return signer, nil
}

// EncodeCertificateToPEM encodes a certificate to PEM format.
func (s *Service) EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// EncodeKeyToPEM encodes an unencrypted private key to PEM format.
func (s *Service) EncodeKeyToPEM(key crypto.Signer) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

// ParseCertificate parses a PEM-encoded certificate.
func (s *Service) ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKey parses an unencrypted PEM-encoded private key.
func (s *Service) ParsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback for older PKCS#1 RSA keys
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		// Fallback for older EC keys
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a crypto.Signer")
	}
	return signer, nil
}

// ParseCSR parses a PEM-encoded Certificate Signing Request.
func (s *Service) ParseCSR(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing CSR")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ValidateKeyPair checks if a private key and certificate belong together.
func (s *Service) ValidateKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return domain.ErrKeyCertMismatch
		}
	case *ecdsa.PublicKey:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return domain.ErrKeyCertMismatch
		}
	case ed25519.PublicKey:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return domain.ErrKeyCertMismatch
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
	return nil
}

// FormatCertificateInfo provides a human-readable summary of a certificate.
func (s *Service) FormatCertificateInfo(cert *x509.Certificate) string {
	var b strings.Builder
	b.WriteString("Certificate:\n")
	b.WriteString(fmt.Sprintf("    Version: %d\n", cert.Version))
	b.WriteString(fmt.Sprintf("    Serial Number: %s\n", cert.SerialNumber))
	b.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm))
	b.WriteString(fmt.Sprintf("    Issuer: %s\n", cert.Issuer.String()))
	b.WriteString("    Validity:\n")
	b.WriteString(fmt.Sprintf("        Not Before: %s\n", cert.NotBefore.Format(time.RFC1123)))
	b.WriteString(fmt.Sprintf("        Not After : %s\n", cert.NotAfter.Format(time.RFC1123)))
	b.WriteString(fmt.Sprintf("    Subject: %s\n", cert.Subject.String()))
	b.WriteString("    Subject Public Key Info:\n")
	b.WriteString(fmt.Sprintf("        Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm))
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		b.WriteString("    X509v3 Subject Alternative Name:\n")
		if len(cert.DNSNames) > 0 {
			b.WriteString(fmt.Sprintf("        DNS: %s\n", strings.Join(cert.DNSNames, ", ")))
		}
		if len(cert.IPAddresses) > 0 {
			var ips []string
			for _, ip := range cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			b.WriteString(fmt.Sprintf("        IP Address: %s\n", strings.Join(ips, ", ")))
		}
	}
	b.WriteString(fmt.Sprintf("    Is CA: %t\n", cert.IsCA))
	return b.String()
}

// createBaseTemplate creates a base certificate template.
func (s *Service) createBaseTemplate(subject *domain.SubjectConfig, validity domain.Validity) (*x509.Certificate, error) {
	serialNumber, err := s.newSerialNumber()
	if err != nil {
		return nil, err
	}

	pkixName := pkix.Name{
		CommonName:         subject.CommonName,
		Organization:       []string{subject.Organization},
		OrganizationalUnit: []string{subject.OrganizationUnit},
		Country:            []string{subject.Country},
		Province:           []string{subject.State},
		Locality:           []string{subject.Locality},
	}
	if subject.Email != "" {
		if _, err := mail.ParseAddress(subject.Email); err == nil {
			pkixName.ExtraNames = append(pkixName.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{1, 2, 840, 113549, 1, 9, 1}, // OID for email address
				Value: subject.Email,
			})
		}
	}

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkixName,
		NotBefore:             time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:              time.Now().Add(validity.ToDuration()).UTC(),
		BasicConstraintsValid: true,
	}, nil
}

// newSerialNumber generates a new, large, random serial number.
func (s *Service) newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
