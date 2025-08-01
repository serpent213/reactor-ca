package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/url"
)

// CRLDistributionPointsExtension implements structured CRL Distribution Points extension
type CRLDistributionPointsExtension struct {
	Critical           bool
	DistributionPoints []DistributionPoint
}

// DistributionPoint represents a single CRL distribution point
type DistributionPoint struct {
	URLs    []string `yaml:"urls"`
	Reasons []string `yaml:"reasons,omitempty"`
}

// Name returns the extension name as used in YAML configuration
func (e *CRLDistributionPointsExtension) Name() string {
	return "crl_distribution_points"
}

// OID returns the CRL Distribution Points OID
func (e *CRLDistributionPointsExtension) OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 31}
}

// ParseFromYAML parses the crl_distribution_points configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	distribution_points: array of distribution points (required)
//	  - urls: array of URLs (required)
//	    reasons: array of revocation reasons (optional)
//
// Example:
//
//	crl_distribution_points:
//	  critical: false
//	  distribution_points:
//	    - urls:
//	        - "http://crl.example.com/ca.crl"
//	        - "ldap://ldap.example.com/cn=CA,dc=example,dc=com"
//	      reasons: [key_compromise, ca_compromise]
func (e *CRLDistributionPointsExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical

	// Parse distribution_points array
	dpInterface, ok := data["distribution_points"]
	if !ok {
		return fmt.Errorf("distribution_points field is required")
	}

	dpArray, ok := dpInterface.([]interface{})
	if !ok {
		return fmt.Errorf("distribution_points must be an array")
	}

	if len(dpArray) == 0 {
		return fmt.Errorf("distribution_points array cannot be empty")
	}

	e.DistributionPoints = make([]DistributionPoint, len(dpArray))

	for i, dpInterface := range dpArray {
		dpMap, ok := dpInterface.(map[string]interface{})
		if !ok {
			return fmt.Errorf("distribution_points[%d] must be an object", i)
		}

		dp := &e.DistributionPoints[i]

		// Parse URLs (required)
		urlsInterface, ok := dpMap["urls"]
		if !ok {
			return fmt.Errorf("distribution_points[%d].urls field is required", i)
		}

		urlsArray, ok := urlsInterface.([]interface{})
		if !ok {
			return fmt.Errorf("distribution_points[%d].urls must be an array", i)
		}

		if len(urlsArray) == 0 {
			return fmt.Errorf("distribution_points[%d].urls array cannot be empty", i)
		}

		dp.URLs = make([]string, len(urlsArray))
		for j, urlInterface := range urlsArray {
			urlStr, ok := urlInterface.(string)
			if !ok {
				return fmt.Errorf("distribution_points[%d].urls[%d] must be a string", i, j)
			}

			// Validate URL format
			if _, err := url.Parse(urlStr); err != nil {
				return fmt.Errorf("distribution_points[%d].urls[%d] is not a valid URL: %v", i, j, err)
			}

			dp.URLs[j] = urlStr
		}

		// Parse reasons (optional)
		if reasonsInterface, exists := dpMap["reasons"]; exists {
			reasonsArray, ok := reasonsInterface.([]interface{})
			if !ok {
				return fmt.Errorf("distribution_points[%d].reasons must be an array", i)
			}

			dp.Reasons = make([]string, len(reasonsArray))
			for j, reasonInterface := range reasonsArray {
				reasonStr, ok := reasonInterface.(string)
				if !ok {
					return fmt.Errorf("distribution_points[%d].reasons[%d] must be a string", i, j)
				}

				// Validate reason
				if !isValidCRLReason(reasonStr) {
					return fmt.Errorf("distribution_points[%d].reasons[%d] is not a valid CRL reason: %s", i, j, reasonStr)
				}

				dp.Reasons[j] = reasonStr
			}
		}
	}

	return nil
}

// ApplyToCertificate applies the CRL Distribution Points extension to an x509.Certificate template
func (e *CRLDistributionPointsExtension) ApplyToCertificate(cert *x509.Certificate) error {
	// Encode the distribution points as ASN.1
	asn1Data, err := e.encodeASN1()
	if err != nil {
		return fmt.Errorf("failed to encode CRL distribution points as ASN.1: %v", err)
	}

	// Add as extra extension since Go's x509 package doesn't have a direct field for this
	extension := pkix.Extension{
		Id:       e.OID(),
		Critical: e.Critical,
		Value:    asn1Data,
	}

	cert.ExtraExtensions = append(cert.ExtraExtensions, extension)
	return nil
}

// ASN.1 structures for CRL Distribution Points
type crlDistributionPoints []distributionPoint

type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reasons           asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         []generalName         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName []generalName `asn1:"optional,tag:0"`
}

type generalName struct {
	URI string `asn1:"tag:6"`
}

// encodeASN1 encodes CRL Distribution Points according to RFC 5280
func (e *CRLDistributionPointsExtension) encodeASN1() ([]byte, error) {
	var distPoints crlDistributionPoints

	for _, dp := range e.DistributionPoints {
		// Create distribution point
		distPoint := distributionPoint{}

		// Add URLs as GeneralNames
		if len(dp.URLs) > 0 {
			var generalNames []generalName
			for _, url := range dp.URLs {
				generalNames = append(generalNames, generalName{URI: url})
			}
			distPoint.DistributionPoint = distributionPointName{
				FullName: generalNames,
			}
		}

		// Add reasons if specified
		if len(dp.Reasons) > 0 {
			reasonFlags := asn1.BitString{}
			for _, reason := range dp.Reasons {
				bit := getCRLReasonBit(reason)
				if bit >= 0 {
					// Set the appropriate bit
					if bit >= len(reasonFlags.Bytes)*8 {
						// Extend the bit string if needed
						newSize := (bit/8 + 1)
						newBytes := make([]byte, newSize)
						copy(newBytes, reasonFlags.Bytes)
						reasonFlags.Bytes = newBytes
					}
					byteIndex := bit / 8
					bitIndex := 7 - (bit % 8) // MSB first
					reasonFlags.Bytes[byteIndex] |= 1 << bitIndex
				}
			}
			distPoint.Reasons = reasonFlags
		}

		distPoints = append(distPoints, distPoint)
	}

	return asn1.Marshal(distPoints)
}

// isValidCRLReason checks if a CRL reason string is valid
func isValidCRLReason(reason string) bool {
	validReasons := []string{
		"unspecified", "key_compromise", "ca_compromise", "affiliation_changed",
		"superseded", "cessation_of_operation", "certificate_hold",
		"privilege_withdrawn", "aa_compromise",
	}

	for _, valid := range validReasons {
		if reason == valid {
			return true
		}
	}
	return false
}

// getCRLReasonBit returns the bit position for a CRL reason
func getCRLReasonBit(reason string) int {
	reasonBits := map[string]int{
		"unspecified":            0,
		"key_compromise":         1,
		"ca_compromise":          2,
		"affiliation_changed":    3,
		"superseded":             4,
		"cessation_of_operation": 5,
		"certificate_hold":       6,
		"privilege_withdrawn":    7,
		"aa_compromise":          8,
	}

	if bit, ok := reasonBits[reason]; ok {
		return bit
	}
	return -1
}
