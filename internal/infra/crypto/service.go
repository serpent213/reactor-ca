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
	"time"

	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/crypto/extensions"
)

// Service implements the domain.CryptoService interface.
type Service struct {
	extensionFactory domain.ExtensionFactory
	clock            domain.Clock
}

// NewService creates a new crypto service with extension support.
func NewService(clock domain.Clock) *Service {
	return &Service{
		extensionFactory: extensions.NewRegistry(),
		clock:            clock,
	}
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

	template.SignatureAlgorithm = s.getSignatureAlgorithm(cfg.CA.HashAlgorithm, key)

	// Apply extensions from configuration, with default CA extensions if none specified
	if err := s.applyExtensions(template, cfg.CA.Extensions, s.defaultCAExtensions()); err != nil {
		return nil, fmt.Errorf("failed to apply extensions: %w", err)
	}

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

	// Set signature algorithm based on hash algorithm and CA key type
	template.SignatureAlgorithm = s.getSignatureAlgorithm(hostCfg.HashAlgorithm, caKey)

	// Set Subject Alternative Names
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

	// Apply extensions from configuration, with default host extensions if none specified
	if err := s.applyExtensions(template, hostCfg.Extensions, s.defaultHostExtensions()); err != nil {
		return nil, fmt.Errorf("failed to apply extensions: %w", err)
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
		NotBefore:      s.clock.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       s.clock.Now().AddDate(0, 0, validityDays).UTC(),
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	// Apply default host extensions for CSR signing
	if err := s.applyExtensions(template, nil, s.defaultHostExtensions()); err != nil {
		return nil, fmt.Errorf("failed to apply extensions: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}
	return x509.ParseCertificate(derBytes)
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

// stringToSlice converts a string to a []string slice, returning nil for empty strings
// to avoid creating empty RDNs in certificates.
func stringToSlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// createBaseTemplate creates a base certificate template.
func (s *Service) createBaseTemplate(subject *domain.SubjectConfig, validity domain.Validity) (*x509.Certificate, error) {
	serialNumber, err := s.newSerialNumber()
	if err != nil {
		return nil, err
	}

	pkixName := pkix.Name{
		CommonName:         subject.CommonName,
		Organization:       stringToSlice(subject.Organization),
		OrganizationalUnit: stringToSlice(subject.OrganizationalUnit),
		Country:            stringToSlice(subject.Country),
		Province:           stringToSlice(subject.State),
		Locality:           stringToSlice(subject.Locality),
	}
	if subject.Email != "" {
		if _, err := mail.ParseAddress(subject.Email); err == nil {
			pkixName.ExtraNames = append(pkixName.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{1, 2, 840, 113549, 1, 9, 1}, // OID for email address
				Value: subject.Email,
			})
		}
	}

	now := s.clock.Now()
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkixName,
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.AddDate(validity.Years, validity.Months, validity.Days).UTC(),
		BasicConstraintsValid: true,
	}, nil
}

// newSerialNumber generates a new, large, random serial number.
func (s *Service) newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// getSignatureAlgorithm determines the x509.SignatureAlgorithm based on hash algorithm and key type.
func (s *Service) getSignatureAlgorithm(hashAlgo domain.HashAlgorithm, key crypto.Signer) x509.SignatureAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		switch hashAlgo {
		case domain.SHA256:
			return x509.SHA256WithRSA
		case domain.SHA384:
			return x509.SHA384WithRSA
		case domain.SHA512:
			return x509.SHA512WithRSA
		default:
			return x509.SHA256WithRSA
		}
	case *ecdsa.PrivateKey:
		switch hashAlgo {
		case domain.SHA256:
			return x509.ECDSAWithSHA256
		case domain.SHA384:
			return x509.ECDSAWithSHA384
		case domain.SHA512:
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA384
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519
	default:
		return x509.SHA256WithRSA
	}
}

// applyExtensions applies extensions from config to the certificate template
// Defaults are applied first, then user config is merged on top (allowing partial overrides)
func (s *Service) applyExtensions(cert *x509.Certificate, config domain.ExtensionsConfig, defaults domain.ExtensionsConfig) error {
	// Merge defaults with user config - user config overrides defaults
	mergedConfig := s.mergeExtensions(defaults, config)

	for name, rawConfig := range mergedConfig {
		// Try to create a known extension first
		ext := s.extensionFactory.CreateExtension(name)

		// If not a known extension, try as unknown extension with OID
		if ext == nil {
			ext = &extensions.UnknownExtension{}
		}

		// Parse the extension configuration
		if err := ext.ParseFromYAML(rawConfig.Critical, rawConfig.Fields); err != nil {
			return fmt.Errorf("failed to parse extension '%s': %w", name, err)
		}

		// Apply the extension to the certificate
		if err := ext.ApplyToCertificate(cert); err != nil {
			return fmt.Errorf("failed to apply extension '%s': %w", name, err)
		}
	}

	return nil
}

// mergeExtensions merges defaults with user config at the field level
// For each extension, default fields are applied first, then user fields override/extend them
func (s *Service) mergeExtensions(defaults, userConfig domain.ExtensionsConfig) domain.ExtensionsConfig {
	merged := make(domain.ExtensionsConfig)

	// Start with defaults
	for name, defaultExt := range defaults {
		merged[name] = domain.ExtensionRawConfig{
			Critical: defaultExt.Critical,
			Fields:   make(map[string]interface{}),
		}

		// Copy default fields
		for field, value := range defaultExt.Fields {
			merged[name].Fields[field] = value
		}
	}

	// Merge user config at field level
	for name, userExt := range userConfig {
		if existingExt, exists := merged[name]; exists {
			// Extension exists in defaults - merge fields
			merged[name] = domain.ExtensionRawConfig{
				Critical: userExt.Critical, // User critical flag takes precedence
				Fields:   existingExt.Fields,
			}
			// Override/add user fields
			for field, value := range userExt.Fields {
				merged[name].Fields[field] = value
			}
		} else {
			// New extension not in defaults - add as-is
			merged[name] = domain.ExtensionRawConfig{
				Critical: userExt.Critical,
				Fields:   make(map[string]interface{}),
			}
			for field, value := range userExt.Fields {
				merged[name].Fields[field] = value
			}
		}
	}

	return merged
}

// defaultCAExtensions returns the default extensions for CA certificates
// This maintains backward compatibility with the previous hardcoded behavior
func (s *Service) defaultCAExtensions() domain.ExtensionsConfig {
	return domain.ExtensionsConfig{
		"basic_constraints": {
			Critical: true,
			Fields: map[string]interface{}{
				"ca": true,
			},
		},
		"key_usage": {
			Critical: true,
			Fields: map[string]interface{}{
				"key_cert_sign": true,
				"crl_sign":      true,
			},
		},
	}
}

// defaultHostExtensions returns the default extensions for host certificates
// This maintains backward compatibility with the previous hardcoded behavior
func (s *Service) defaultHostExtensions() domain.ExtensionsConfig {
	return domain.ExtensionsConfig{
		"key_usage": {
			Critical: false,
			Fields: map[string]interface{}{
				"digital_signature": true,
				"key_encipherment":  true,
			},
		},
		"extended_key_usage": {
			Critical: false,
			Fields: map[string]interface{}{
				"server_auth": true,
				"client_auth": true,
			},
		},
	}
}
