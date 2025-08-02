package ui

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

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

// Individual parser functions for each extension type

func parseKeyUsage(cert *x509.Certificate) map[string]string {
	values := make(map[string]string)
	if cert.KeyUsage != 0 {
		var usages []string
		usageMap := map[x509.KeyUsage]string{
			x509.KeyUsageDigitalSignature:  "Digital Signature",
			x509.KeyUsageContentCommitment: "Content Commitment (Non-Repudiation)",
			x509.KeyUsageKeyEncipherment:   "Key Encipherment",
			x509.KeyUsageDataEncipherment:  "Data Encipherment",
			x509.KeyUsageKeyAgreement:      "Key Agreement",
			x509.KeyUsageCertSign:          "Certificate Sign",
			x509.KeyUsageCRLSign:           "CRL Sign",
			x509.KeyUsageEncipherOnly:      "Encipher Only",
			x509.KeyUsageDecipherOnly:      "Decipher Only",
		}

		for usage, name := range usageMap {
			if cert.KeyUsage&usage != 0 {
				usages = append(usages, name)
			}
		}

		if len(usages) > 0 {
			values["Usage"] = strings.Join(usages, ", ")
		}
	}
	return values
}

func parseExtendedKeyUsage(cert *x509.Certificate) map[string]string {
	values := make(map[string]string)
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		var usages []string

		// Known extended key usages
		usageMap := map[x509.ExtKeyUsage]string{
			x509.ExtKeyUsageServerAuth:                     "Server Authentication",
			x509.ExtKeyUsageClientAuth:                     "Client Authentication",
			x509.ExtKeyUsageCodeSigning:                    "Code Signing",
			x509.ExtKeyUsageEmailProtection:                "Email Protection",
			x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
			x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
			x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
			x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
			x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
		}

		for _, usage := range cert.ExtKeyUsage {
			if name, exists := usageMap[usage]; exists {
				usages = append(usages, name)
			} else {
				usages = append(usages, fmt.Sprintf("Unknown (%d)", usage))
			}
		}

		// Unknown extended key usages (by OID)
		for _, oid := range cert.UnknownExtKeyUsage {
			usages = append(usages, fmt.Sprintf("Custom OID: %s", oid.String()))
		}

		if len(usages) > 0 {
			values["Usage"] = strings.Join(usages, "\n")
		}
	}
	return values
}

func parseBasicConstraints(cert *x509.Certificate) map[string]string {
	values := make(map[string]string)

	if cert.IsCA {
		pathLen := "unlimited"
		if cert.MaxPathLen >= 0 {
			pathLen = fmt.Sprintf("%d", cert.MaxPathLen)
		} else if cert.MaxPathLenZero {
			pathLen = "0"
		}
		values["CA"] = fmt.Sprintf("%t", cert.IsCA)
		values["Path Length Constraint"] = pathLen
	} else {
		values["CA"] = fmt.Sprintf("%t", cert.IsCA)
	}

	return values
}

func parseSubjectAltName(cert *x509.Certificate) map[string]string {
	values := make(map[string]string)

	var names []string
	for _, dns := range cert.DNSNames {
		names = append(names, fmt.Sprintf("DNS: %s", dns))
	}
	for _, email := range cert.EmailAddresses {
		names = append(names, fmt.Sprintf("Email: %s", email))
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, fmt.Sprintf("IP: %s", ip.String()))
	}
	for _, uri := range cert.URIs {
		names = append(names, fmt.Sprintf("URI: %s", uri.String()))
	}

	if len(names) > 0 {
		values["Alternative Names"] = strings.Join(names, "\n")
	}

	return values
}

func parseIssuerAltName(cert *x509.Certificate) map[string]string {
	// Note: Go's x509 package doesn't expose issuer alt names directly
	// Would need to parse the extension manually
	return parseGenericASN1Extension("Issuer Alternative Names", nil)
}

func parseSubjectKeyIdentifier(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var keyId []byte
	if _, err := asn1.Unmarshal(ext.Value, &keyId); err == nil {
		values["Key Identifier"] = fmt.Sprintf("%s (%d bytes)",
			strings.ToUpper(hex.EncodeToString(keyId)), len(keyId))
	}

	return values
}

func parseAuthorityKeyIdentifier(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	// AuthorityKeyIdentifier structure
	type authorityKeyId struct {
		KeyIdentifier             []byte          `asn1:"optional,tag:0"`
		AuthorityCertIssuer       []asn1.RawValue `asn1:"optional,tag:1"`
		AuthorityCertSerialNumber *big.Int        `asn1:"optional,tag:2"`
	}

	var akid authorityKeyId
	if _, err := asn1.Unmarshal(ext.Value, &akid); err == nil {
		if len(akid.KeyIdentifier) > 0 {
			values["Key Identifier"] = fmt.Sprintf("%s (%d bytes)",
				strings.ToUpper(hex.EncodeToString(akid.KeyIdentifier)), len(akid.KeyIdentifier))
		}
		if akid.AuthorityCertSerialNumber != nil {
			values["Authority Cert Serial"] = akid.AuthorityCertSerialNumber.String()
		}
		if len(akid.AuthorityCertIssuer) > 0 {
			values["Authority Cert Issuer"] = fmt.Sprintf("(%d names)", len(akid.AuthorityCertIssuer))
		}
	}

	return values
}

func parseCRLDistributionPoints(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	// Simplified CRL distribution points parsing
	var rawValues []asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &rawValues); err == nil {
		var urls []string
		for i, rawValue := range rawValues {
			// This is a simplified approach - full parsing would be more complex
			if strings.Contains(string(rawValue.Bytes), "http") {
				start := strings.Index(string(rawValue.Bytes), "http")
				url := string(rawValue.Bytes[start:])
				// Clean up the URL (remove non-printable characters)
				cleanUrl := ""
				for _, char := range url {
					if char >= 32 && char <= 126 {
						cleanUrl += string(char)
					} else {
						break
					}
				}
				if cleanUrl != "" {
					urls = append(urls, cleanUrl)
				}
			} else {
				urls = append(urls, fmt.Sprintf("Distribution Point %d: (binary data)", i+1))
			}
		}
		if len(urls) > 0 {
			values["Distribution Points"] = strings.Join(urls, "\n")
		}
	}

	return values
}

func parseAuthorityInfoAccess(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	// AccessDescription structure
	type accessDescription struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue `asn1:"tag:6"` // GeneralName with URI tag
	}

	var descriptions []accessDescription
	if _, err := asn1.Unmarshal(ext.Value, &descriptions); err == nil {
		var info []string
		for _, desc := range descriptions {
			method := "Unknown Method"
			switch desc.Method.String() {
			case "1.3.6.1.5.5.7.48.1":
				method = "OCSP"
			case "1.3.6.1.5.5.7.48.2":
				method = "CA Issuers"
			}

			location := string(desc.Location.Bytes)
			info = append(info, fmt.Sprintf("%s: %s", method, location))
		}
		if len(info) > 0 {
			values["Access Information"] = strings.Join(info, "\n")
		}
	}

	return values
}

func parseSubjectInfoAccess(ext pkix.Extension) map[string]string {
	// Similar to Authority Info Access but for subject
	return parseAuthorityInfoAccess(ext) // Reuse the same structure
}

func parseCertificatePolicies(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	type policyInformation struct {
		Policy     asn1.ObjectIdentifier
		Qualifiers []asn1.RawValue `asn1:"optional"`
	}

	var policies []policyInformation
	if _, err := asn1.Unmarshal(ext.Value, &policies); err == nil {
		var policyList []string
		for _, policy := range policies {
			policyStr := policy.Policy.String()
			if policyStr == "2.5.29.32.0" {
				policyStr += " (anyPolicy)"
			}
			policyList = append(policyList, policyStr)
		}
		if len(policyList) > 0 {
			values["Policies"] = strings.Join(policyList, "\n")
		}
	}

	return values
}

func parseNameConstraints(ext pkix.Extension) map[string]string {
	return parseGenericASN1Extension("Name Constraints", ext.Value)
}

func parsePolicyMappings(ext pkix.Extension) map[string]string {
	return parseGenericASN1Extension("Policy Mappings", ext.Value)
}

func parsePolicyConstraints(ext pkix.Extension) map[string]string {
	return parseGenericASN1Extension("Policy Constraints", ext.Value)
}

func parseInhibitAnyPolicy(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var skipCerts int
	if _, err := asn1.Unmarshal(ext.Value, &skipCerts); err == nil {
		values["Skip Certificates"] = fmt.Sprintf("%d", skipCerts)
	}

	return values
}

func parseSubjectDirectoryAttributes(ext pkix.Extension) map[string]string {
	return parseGenericASN1Extension("Subject Directory Attributes", ext.Value)
}

func parseCTSCTList(ext pkix.Extension) map[string]string {
	values := make(map[string]string)
	values["Certificate Transparency"] = "SCT List present"
	values["Data Length"] = fmt.Sprintf("%d bytes", len(ext.Value))
	return values
}

func parseMicrosoftTemplateName(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var templateName string
	if _, err := asn1.Unmarshal(ext.Value, &templateName); err == nil {
		values["Template Name"] = templateName
	}

	return values
}

func parseMicrosoftTemplateInfo(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	type templateInfo struct {
		TemplateID   asn1.ObjectIdentifier
		MajorVersion int `asn1:"optional"`
		MinorVersion int `asn1:"optional"`
	}

	var info templateInfo
	if _, err := asn1.Unmarshal(ext.Value, &info); err == nil {
		values["Template OID"] = info.TemplateID.String()
		if info.MajorVersion > 0 {
			values["Major Version"] = fmt.Sprintf("%d", info.MajorVersion)
		}
		if info.MinorVersion > 0 {
			values["Minor Version"] = fmt.Sprintf("%d", info.MinorVersion)
		}
	}

	return values
}

func parseNetscapeCertType(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var certType asn1.BitString
	if _, err := asn1.Unmarshal(ext.Value, &certType); err == nil {
		var types []string
		typeMap := map[int]string{
			0: "SSL Client",
			1: "SSL Server",
			2: "S/MIME",
			3: "Object Signing",
			4: "Reserved",
			5: "SSL CA",
			6: "S/MIME CA",
			7: "Object Signing CA",
		}

		for bit, typeName := range typeMap {
			if certType.At(bit) == 1 {
				types = append(types, typeName)
			}
		}

		if len(types) > 0 {
			values["Certificate Types"] = strings.Join(types, ", ")
		}
	}

	return values
}

func parseNetscapeComment(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var comment string
	if _, err := asn1.Unmarshal(ext.Value, &comment); err == nil {
		values["Comment"] = comment
	}

	return values
}

func parseTLSFeature(ext pkix.Extension) map[string]string {
	values := make(map[string]string)

	var features []int
	if _, err := asn1.Unmarshal(ext.Value, &features); err == nil {
		var featureNames []string
		for _, feature := range features {
			switch feature {
			case 5:
				featureNames = append(featureNames, "status_request (OCSP Must-Staple)")
			case 17:
				featureNames = append(featureNames, "status_request_v2")
			default:
				featureNames = append(featureNames, fmt.Sprintf("Unknown Feature %d", feature))
			}
		}
		if len(featureNames) > 0 {
			values["TLS Features"] = strings.Join(featureNames, "\n")
		}
	}

	return values
}

func parseGenericASN1(ext pkix.Extension) map[string]string {
	return parseGenericASN1Extension("Generic ASN.1 Data", ext.Value)
}

func parseGenericASN1Extension(name string, data []byte) map[string]string {
	values := make(map[string]string)

	if len(data) == 0 {
		values["Value"] = "Empty"
		return values
	}

	// Try to parse as various ASN.1 types

	// Try as OCTET STRING
	var octets []byte
	if _, err := asn1.Unmarshal(data, &octets); err == nil && len(octets) > 0 {
		values["Octet String"] = fmt.Sprintf("%s (%d bytes)",
			hex.EncodeToString(octets), len(octets))
	}

	// Try as INTEGER
	var intVal int
	if _, err := asn1.Unmarshal(data, &intVal); err == nil {
		values["Integer"] = fmt.Sprintf("%d", intVal)
	}

	// Try as BOOLEAN
	var boolVal bool
	if _, err := asn1.Unmarshal(data, &boolVal); err == nil {
		values["Boolean"] = fmt.Sprintf("%t", boolVal)
	}

	// Try as IA5String (ASCII)
	var stringVal string
	if _, err := asn1.Unmarshal(data, &stringVal); err == nil && isPrintableASCII(stringVal) {
		values["String"] = stringVal
	}

	// Try as BIT STRING
	var bitString asn1.BitString
	if _, err := asn1.Unmarshal(data, &bitString); err == nil {
		values["Bit String"] = fmt.Sprintf("%d bits", bitString.BitLength)
	}

	// Try as SEQUENCE
	var sequence []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &sequence); err == nil && len(sequence) > 0 {
		values["Sequence"] = fmt.Sprintf("%d elements", len(sequence))
	}

	// Fallback: show raw hex
	if len(values) == 0 {
		values["Raw Hex"] = hex.EncodeToString(data)
	}

	return values
}

// Helper functions for formatting and display

func indentText(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func isPrintableASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, char := range s {
		if char < 32 || char > 126 {
			return false
		}
	}
	return true
}
