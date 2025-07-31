package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
)

// NameConstraintsExtension implements the X.509 Name Constraints extension (RFC 5280)
type NameConstraintsExtension struct {
	Critical                bool
	PermittedDNSDomains     []string
	ExcludedDNSDomains      []string
	PermittedIPRanges       []*net.IPNet
	ExcludedIPRanges        []*net.IPNet
	PermittedEmailAddresses []string
	ExcludedEmailAddresses  []string
	PermittedURIDomains     []string
	ExcludedURIDomains      []string
}

// Name returns the extension name as used in YAML configuration
func (e *NameConstraintsExtension) Name() string {
	return "name_constraints"
}

// OID returns empty since this is a built-in extension handled by Go's x509 package
func (e *NameConstraintsExtension) OID() asn1.ObjectIdentifier {
	return nil
}

// ParseFromYAML parses the name_constraints configuration from YAML
// Supported fields:
//
//	critical: true/false (required)
//	permitted_dns_domains: []string (DNS domain constraints)
//	excluded_dns_domains: []string (DNS domain constraints)
//	permitted_ip_ranges: []string (IP range constraints in CIDR format)
//	excluded_ip_ranges: []string (IP range constraints in CIDR format)
//	permitted_email_addresses: []string (Email address constraints)
//	excluded_email_addresses: []string (Email address constraints)
//	permitted_uri_domains: []string (URI domain constraints)
//	excluded_uri_domains: []string (URI domain constraints)
func (e *NameConstraintsExtension) ParseFromYAML(critical bool, data map[string]interface{}) error {
	e.Critical = critical

	// Parse DNS domain constraints
	e.PermittedDNSDomains = parseStringSlice(data, "permitted_dns_domains")
	e.ExcludedDNSDomains = parseStringSlice(data, "excluded_dns_domains")

	// Parse IP range constraints
	permittedIPStrings := parseStringSlice(data, "permitted_ip_ranges")
	excludedIPStrings := parseStringSlice(data, "excluded_ip_ranges")

	var err error
	e.PermittedIPRanges, err = parseIPRanges(permittedIPStrings)
	if err != nil {
		return fmt.Errorf("invalid permitted_ip_ranges: %v", err)
	}

	e.ExcludedIPRanges, err = parseIPRanges(excludedIPStrings)
	if err != nil {
		return fmt.Errorf("invalid excluded_ip_ranges: %v", err)
	}

	// Parse email address constraints
	e.PermittedEmailAddresses = parseStringSlice(data, "permitted_email_addresses")
	e.ExcludedEmailAddresses = parseStringSlice(data, "excluded_email_addresses")

	// Parse URI domain constraints
	e.PermittedURIDomains = parseStringSlice(data, "permitted_uri_domains")
	e.ExcludedURIDomains = parseStringSlice(data, "excluded_uri_domains")

	return nil
}

// ApplyToCertificate applies the Name Constraints extension to an x509.Certificate template
func (e *NameConstraintsExtension) ApplyToCertificate(cert *x509.Certificate) error {
	// Set DNS domain constraints
	cert.PermittedDNSDomains = e.PermittedDNSDomains
	cert.ExcludedDNSDomains = e.ExcludedDNSDomains

	// Set IP range constraints
	cert.PermittedIPRanges = e.PermittedIPRanges
	cert.ExcludedIPRanges = e.ExcludedIPRanges

	// Set email address constraints
	cert.PermittedEmailAddresses = e.PermittedEmailAddresses
	cert.ExcludedEmailAddresses = e.ExcludedEmailAddresses

	// Set URI domain constraints
	cert.PermittedURIDomains = e.PermittedURIDomains
	cert.ExcludedURIDomains = e.ExcludedURIDomains

	// Set the critical flag
	cert.PermittedDNSDomainsCritical = e.Critical

	return nil
}

// parseIPRanges converts a slice of CIDR strings to []*net.IPNet
func parseIPRanges(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	ranges := make([]*net.IPNet, len(cidrs))
	for i, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %v", cidr, err)
		}
		ranges[i] = ipNet
	}

	return ranges, nil
}
