package ui

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// formatDurationParts formats a duration into human-readable parts
func formatDurationParts(duration time.Duration, p *message.Printer) string {
	days := int64(math.Round(duration.Hours() / 24))
	totalHours := int64(duration.Hours())

	if days == 0 && totalHours == 0 {
		return "today"
	} else if days < 3 {
		// Show total hours for durations less than 3 days
		if days == 0 {
			return p.Sprintf("%d hours", totalHours)
		} else if days == 1 {
			return p.Sprintf("1 day (%d hours)", totalHours)
		} else { // days == 2
			return p.Sprintf("%d days (%d hours)", days, totalHours)
		}
	} else if days <= 365 {
		return p.Sprintf("%d days", days)
	} else {
		// Calculate years with 1 decimal place using proper calendar arithmetic
		now := time.Now()
		oneYearLater := now.AddDate(1, 0, 0)
		daysInYear := float64(oneYearLater.Sub(now).Hours() / 24)
		years := float64(days) / daysInYear
		return p.Sprintf("%d days (%.1f years)", days, years)
	}
}

// FormatCertExpiry formats certificate expiry time in a user-friendly way with colored status symbols
func FormatCertExpiry(expiryTime time.Time, criticalDays, warningDays int) string {
	p := message.NewPrinter(getUserLocale())
	now := time.Now()
	duration := expiryTime.Sub(now)

	var timeString string
	if duration >= 0 {
		// Certificate has not expired yet
		formatted := formatDurationParts(duration, p)
		if formatted == "today" {
			timeString = "Expires today"
		} else {
			timeString = formatted
		}
	} else {
		// Certificate has expired
		expiredDuration := -duration // Make it positive for formatting
		formatted := formatDurationParts(expiredDuration, p)
		if formatted == "today" {
			timeString = "EXPIRED today"
		} else {
			timeString = "EXPIRED " + formatted + " ago"
		}
	}

	// Add colored status symbols based on configurable thresholds
	days := int64(math.Round(duration.Hours() / 24))
	if days < 0 {
		return red("✗") + " " + timeString
	} else if days <= int64(criticalDays) {
		return red("✗") + " " + timeString
	} else if days <= int64(warningDays) {
		return yellow("!") + " " + timeString
	} else {
		return green("✓") + " " + timeString
	}
}

// PrintCertInfo displays certificate information in a user-friendly format
func PrintCertInfo(cert *x509.Certificate, criticalDays, warningDays int) {
	// Calculate validity status
	remaining := FormatCertExpiry(cert.NotAfter, criticalDays, warningDays)

	// Extract email from certificate subject
	email := extractEmailFromSubject(cert.Subject)

	// Build organization info
	org := ""
	var orgParts []string
	if len(cert.Subject.Organization) > 0 && cert.Subject.Organization[0] != "" {
		orgParts = append(orgParts, cert.Subject.Organization[0])
	}
	if len(cert.Subject.OrganizationalUnit) > 0 && cert.Subject.OrganizationalUnit[0] != "" {
		orgParts = append(orgParts, cert.Subject.OrganizationalUnit[0])
	}
	if len(orgParts) > 0 {
		org = strings.Join(orgParts, ", ")
	}

	// Build location info
	location := ""
	var locParts []string
	if len(cert.Subject.Locality) > 0 && cert.Subject.Locality[0] != "" {
		locParts = append(locParts, cert.Subject.Locality[0])
	}
	if len(cert.Subject.Province) > 0 && cert.Subject.Province[0] != "" {
		locParts = append(locParts, cert.Subject.Province[0])
	}
	if len(cert.Subject.Country) > 0 && cert.Subject.Country[0] != "" {
		locParts = append(locParts, cert.Subject.Country[0])
	}
	if len(locParts) > 0 {
		location = strings.Join(locParts, ", ")
	}

	// Get key type details
	keyType := getKeyTypeDetails(cert.PublicKey)

	// Generate fingerprint
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	fmt.Println()
	// Use appropriate header based on certificate type
	header := "CERTIFICATE"
	if cert.IsCA {
		header = "CERTIFICATE AUTHORITY"
	}
	fmt.Printf("%s\n", green(bold(header)))

	// Certificate details section
	if cert.Subject.CommonName != "" && cert.IsCA {
		fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Name")), cert.Subject.CommonName)
	}
	if org != "" {
		fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Organization")), org)
	}
	if email != "" {
		fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Email")), email)
	}
	if location != "" {
		fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Location")), location)
	}

	// For host certificates, show valid names prominently
	if !cert.IsCA {
		fmt.Printf("\n%s\n", green(bold("SUBJECT NAMES")))

		// Always show Common Name first if present
		if cert.Subject.CommonName != "" {
			fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Common Name")), cert.Subject.CommonName)
		}

		// Show DNS names
		if len(cert.DNSNames) > 0 {
			for i, dns := range cert.DNSNames {
				label := "DNS"
				if i > 0 {
					label = ""
				}
				fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", label)), dns)
			}
		}

		// Show IP addresses
		if len(cert.IPAddresses) > 0 {
			for i, ip := range cert.IPAddresses {
				label := "IP Address"
				if i > 0 {
					label = ""
				}
				fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", label)), ip.String())
			}
		}

		// Show email addresses if present
		if len(cert.EmailAddresses) > 0 {
			for i, email := range cert.EmailAddresses {
				label := "Email"
				if i > 0 {
					label = ""
				}
				fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", label)), email)
			}
		}

		// Show URIs if present
		if len(cert.URIs) > 0 {
			for i, uri := range cert.URIs {
				label := "URI"
				if i > 0 {
					label = ""
				}
				fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", label)), uri.String())
			}
		}
	}

	fmt.Printf("\n%s\n", green(bold("VALIDITY PERIOD")))
	fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Issued")), cert.NotBefore.Format(time.RFC1123))
	fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Expires")), cert.NotAfter.Format(time.RFC1123))
	fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Remaining")), remaining)

	fmt.Printf("\n%s\n", green(bold("CRYPTOGRAPHIC DETAILS")))
	fmt.Printf("   %s %x\n", cyan(fmt.Sprintf("%-13s", "Serial")), cert.SerialNumber)
	fmt.Printf("   %s SHA256:%s\n", cyan(fmt.Sprintf("%-13s", "Fingerprint")), fingerprint)
	fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Key")), keyType)
	fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%-13s", "Signature")), cert.SignatureAlgorithm)

	// Show extensions if present
	if len(cert.Extensions) > 0 {
		fmt.Printf("\n%s\n", green(bold("EXTENSIONS")))
		printCertExtensions(cert)
	}

	fmt.Println()
}

// getUserLocale detects the user's locale from environment variables
func getUserLocale() language.Tag {
	// Check environment variables in standard precedence order:
	// LC_ALL overrides all, LC_MESSAGES for interface text, LANGUAGE for GNU systems, LANG as fallback
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"} {
		if val := os.Getenv(env); val != "" {
			// Parse locale string (e.g., "en_US.UTF-8" -> "en-US")
			locale := strings.Split(val, ".")[0]
			locale = strings.Replace(locale, "_", "-", -1)

			if tag, err := language.Parse(locale); err == nil {
				return tag
			}
		}
	}

	// Fall back to English if we can't determine locale
	return language.English
}

// extractEmailFromSubject extracts email address from certificate subject
func extractEmailFromSubject(subject pkix.Name) string {
	for _, name := range subject.Names {
		// Email address OID: 1.2.840.113549.1.9.1
		if name.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}) {
			if email, ok := name.Value.(string); ok {
				return email
			}
		}
	}
	return ""
}

// getKeyTypeDetails returns a human-readable description of the public key
func getKeyTypeDetails(pubKey interface{}) string {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d-bit)", key.Size()*8)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA (%s, %d-bit)", key.Curve.Params().Name, key.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519 (256-bit)"
	default:
		return "Unknown"
	}
}

// printCertExtensions displays certificate extensions in a readable format
func printCertExtensions(cert *x509.Certificate) {
	// Comprehensive extension name mapping with all known extensions
	extensionNames := map[string]string{
		// Standard RFC 5280 Extensions
		"2.5.29.9":  "Subject Directory Attributes",
		"2.5.29.14": "Subject Key Identifier",
		"2.5.29.15": "Key Usage",
		"2.5.29.16": "Private Key Usage Period",
		"2.5.29.17": "Subject Alternative Name",
		"2.5.29.18": "Issuer Alternative Name",
		"2.5.29.19": "Basic Constraints",
		"2.5.29.21": "Reason Code",
		"2.5.29.23": "Hold Instruction Code",
		"2.5.29.24": "Invalidity Date",
		"2.5.29.29": "Certificate Issuer",
		"2.5.29.30": "Name Constraints",
		"2.5.29.31": "CRL Distribution Points",
		"2.5.29.32": "Certificate Policies",
		"2.5.29.33": "Policy Mappings",
		"2.5.29.35": "Authority Key Identifier",
		"2.5.29.36": "Policy Constraints",
		"2.5.29.37": "Extended Key Usage",
		"2.5.29.46": "Freshest CRL",
		"2.5.29.54": "Inhibit anyPolicy",

		// PKIX Extensions
		"1.3.6.1.5.5.7.1.1":    "Authority Information Access",
		"1.3.6.1.5.5.7.1.11":   "Subject Information Access",
		"1.3.6.1.5.5.7.1.24":   "TLS Feature",
		"1.3.6.1.5.5.7.48.1.5": "OCSP No Check",

		// Certificate Transparency (RFC 6962)
		"1.3.6.1.4.1.11129.2.4.2": "CT Signed Certificate Timestamp List",
		"1.3.6.1.4.1.11129.2.4.3": "CT Precertificate Poison",

		// Microsoft Extensions
		"1.3.6.1.4.1.311.10.3.1":   "Microsoft Server Gated Crypto",
		"1.3.6.1.4.1.311.10.3.3":   "Microsoft SGC Serialized",
		"1.3.6.1.4.1.311.20.2":     "Microsoft Certificate Template Name",
		"1.3.6.1.4.1.311.21.7":     "Microsoft Certificate Template Information",
		"1.3.6.1.4.1.311.21.10":    "Microsoft Application Policies",
		"1.3.6.1.4.1.311.60.2.1.1": "Microsoft Jurisdiction of Incorporation Locality",
		"1.3.6.1.4.1.311.60.2.1.2": "Microsoft Jurisdiction of Incorporation State",
		"1.3.6.1.4.1.311.60.2.1.3": "Microsoft Jurisdiction of Incorporation Country",

		// Netscape Extensions
		"2.16.840.1.113730.1.1":  "Netscape Certificate Type",
		"2.16.840.1.113730.1.2":  "Netscape Base URL",
		"2.16.840.1.113730.1.3":  "Netscape Revocation URL",
		"2.16.840.1.113730.1.4":  "Netscape CA Revocation URL",
		"2.16.840.1.113730.1.7":  "Netscape Certificate Renewal URL",
		"2.16.840.1.113730.1.8":  "Netscape CA Policy URL",
		"2.16.840.1.113730.1.12": "Netscape SSL Server Name",
		"2.16.840.1.113730.1.13": "Netscape Certificate Comment",

		// Additional Vendor Extensions
		"1.2.840.113549.1.9.15": "SMIMECapabilities",
		"1.2.840.10040.4.5":     "id-dsa-with-sha1",
		"1.3.14.3.2.29":         "id-sha1WithRSAEncryption",
	}

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		name := extensionNames[oidStr]
		if name == "" {
			name = oidStr
		}

		displayName := cyan(name)
		if ext.Critical {
			displayName = displayName + red(" !")
		}

		// Hide OID for known extensions, show for unknown ones
		if extensionNames[oidStr] != "" {
			fmt.Printf("   %s\n", displayName)
		} else {
			fmt.Printf("   %s %s\n", displayName, oidStr)
		}

		// Get and display extension values
		values := resolveExtensionValue(cert, ext, name)
		if len(values) > 0 {
			// Sort keys for consistent display
			var keys []string
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			for _, key := range keys {
				value := values[key]
				if strings.Contains(value, "\n") {
					// Multi-line values
					fmt.Printf("     %s\n%s\n", cyan(key+":"), indentText(value, "       "))
				} else {
					// Single-line values
					fmt.Printf("     %s %s\n", cyan(key+":"), value)
				}
			}
		} else {
			// Fallback: show raw hex data
			fmt.Printf("     %s %s\n", cyan("Raw Data:"), hex.EncodeToString(ext.Value))
		}
	}

	fmt.Printf("\n   %s\n", red("(! = critical)"))
}

// resolveExtensionValue returns parsed extension values for all known extensions
func resolveExtensionValue(cert *x509.Certificate, ext pkix.Extension, name string) map[string]string {
	oidStr := ext.Id.String()

	switch oidStr {
	case "2.5.29.15": // Key Usage
		return parseKeyUsage(cert)

	case "2.5.29.37": // Extended Key Usage
		return parseExtendedKeyUsage(cert)

	case "2.5.29.19": // Basic Constraints
		return parseBasicConstraints(cert)

	case "2.5.29.17": // Subject Alternative Name
		return parseSubjectAltName(cert)

	case "2.5.29.18": // Issuer Alternative Name
		return parseIssuerAltName(cert)

	case "2.5.29.14": // Subject Key Identifier
		return parseSubjectKeyIdentifier(ext)

	case "2.5.29.35": // Authority Key Identifier
		return parseAuthorityKeyIdentifier(ext)

	case "2.5.29.31": // CRL Distribution Points
		return parseCRLDistributionPoints(ext)

	case "1.3.6.1.5.5.7.1.1": // Authority Information Access
		return parseAuthorityInfoAccess(ext)

	case "1.3.6.1.5.5.7.1.11": // Subject Information Access
		return parseSubjectInfoAccess(ext)

	case "2.5.29.32": // Certificate Policies
		return parseCertificatePolicies(ext)

	case "2.5.29.30": // Name Constraints
		return parseNameConstraints(ext)

	case "2.5.29.33": // Policy Mappings
		return parsePolicyMappings(ext)

	case "2.5.29.36": // Policy Constraints
		return parsePolicyConstraints(ext)

	case "2.5.29.54": // Inhibit anyPolicy
		return parseInhibitAnyPolicy(ext)

	case "2.5.29.9": // Subject Directory Attributes
		return parseSubjectDirectoryAttributes(ext)

	case "1.3.6.1.4.1.11129.2.4.2": // CT SCT List
		return parseCTSCTList(ext)

	case "1.3.6.1.4.1.11129.2.4.3": // CT Precertificate Poison
		values := make(map[string]string)
		values["Value"] = "Present (Precertificate Poison)"
		return values

	case "1.3.6.1.4.1.311.20.2": // Microsoft Certificate Template Name
		return parseMicrosoftTemplateName(ext)

	case "1.3.6.1.4.1.311.21.7": // Microsoft Certificate Template Information
		return parseMicrosoftTemplateInfo(ext)

	case "2.16.840.1.113730.1.1": // Netscape Certificate Type
		return parseNetscapeCertType(ext)

	case "2.16.840.1.113730.1.13": // Netscape Certificate Comment
		return parseNetscapeComment(ext)

	case "1.3.6.1.5.5.7.1.24": // TLS Feature
		return parseTLSFeature(ext)

	default:
		// Generic ASN.1 parsing for unknown extensions
		return parseGenericASN1(ext)
	}
}
