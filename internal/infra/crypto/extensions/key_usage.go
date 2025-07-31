package extensions

import (
	"crypto/x509"
	"encoding/asn1"
)

// KeyUsageExtension implements the X.509 Key Usage extension (RFC 5280)
type KeyUsageExtension struct {
	Critical          bool
	DigitalSignature  bool // x509.KeyUsageDigitalSignature
	ContentCommitment bool // x509.KeyUsageContentCommitment (non-repudiation)
	KeyEncipherment   bool // x509.KeyUsageKeyEncipherment
	DataEncipherment  bool // x509.KeyUsageDataEncipherment
	KeyAgreement      bool // x509.KeyUsageKeyAgreement
	KeyCertSign       bool // x509.KeyUsageCertSign
	CRLSign           bool // x509.KeyUsageCRLSign
	EncipherOnly      bool // x509.KeyUsageEncipherOnly
	DecipherOnly      bool // x509.KeyUsageDecipherOnly
}

// Name returns the extension name as used in YAML configuration
func (e *KeyUsageExtension) Name() string {
	return "key_usage"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *KeyUsageExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the key_usage configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	digital_signature: true/false (default: false)
//	content_commitment: true/false (default: false)
//	key_encipherment: true/false (default: false)
//	data_encipherment: true/false (default: false)
//	key_agreement: true/false (default: false)
//	key_cert_sign: true/false (default: false)
//	crl_sign: true/false (default: false)
//	encipher_only: true/false (default: false)
//	decipher_only: true/false (default: false)
func (e *KeyUsageExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical
	e.DigitalSignature = parseFieldAs(data, "digital_signature", false)
	e.ContentCommitment = parseFieldAs(data, "content_commitment", false)
	e.KeyEncipherment = parseFieldAs(data, "key_encipherment", false)
	e.DataEncipherment = parseFieldAs(data, "data_encipherment", false)
	e.KeyAgreement = parseFieldAs(data, "key_agreement", false)
	e.KeyCertSign = parseFieldAs(data, "key_cert_sign", false)
	e.CRLSign = parseFieldAs(data, "crl_sign", false)
	e.EncipherOnly = parseFieldAs(data, "encipher_only", false)
	e.DecipherOnly = parseFieldAs(data, "decipher_only", false)

	return nil
}

// ApplyToCertificate applies the Key Usage extension to an x509.Certificate template
func (e *KeyUsageExtension) ApplyToCertificate(cert *x509.Certificate) error {
	var keyUsage x509.KeyUsage

	if e.DigitalSignature {
		keyUsage |= x509.KeyUsageDigitalSignature
	}
	if e.ContentCommitment {
		keyUsage |= x509.KeyUsageContentCommitment
	}
	if e.KeyEncipherment {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	if e.DataEncipherment {
		keyUsage |= x509.KeyUsageDataEncipherment
	}
	if e.KeyAgreement {
		keyUsage |= x509.KeyUsageKeyAgreement
	}
	if e.KeyCertSign {
		keyUsage |= x509.KeyUsageCertSign
	}
	if e.CRLSign {
		keyUsage |= x509.KeyUsageCRLSign
	}
	if e.EncipherOnly {
		keyUsage |= x509.KeyUsageEncipherOnly
	}
	if e.DecipherOnly {
		keyUsage |= x509.KeyUsageDecipherOnly
	}

	cert.KeyUsage = keyUsage
	return nil
}
