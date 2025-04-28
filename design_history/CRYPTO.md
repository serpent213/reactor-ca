# Cryptographic Analysis of ReactorCA

## Overview

This document analyzes the cryptographic choices made in the ReactorCA tool, their security implications, and provides recommendations for future-proofing while maintaining compatibility with older browsers.

## Key Cryptographic Components

### Key Types

ReactorCA supports two key types:
1. **RSA** - Default for CA (4096 bits) and hosts (2048 bits)
2. **EC** (Elliptic Curve) - Optional with support for SECP256R1 (P-256), SECP384R1 (P-384), and SECP521R1 (P-521)

### Signature Algorithm
- SHA-256 is used for all certificate signatures

### Certificate Formats
- X.509 certificates in PEM format
- PKCS#8 format for private keys

### Key Protection
- Private keys are encrypted using the best available encryption via `BestAvailableEncryption`
- Option for unencrypted keys via `NoEncryption`

## Analysis of Current Implementation

### Strengths

1. **Strong RSA Key Sizes**
   - The default 4096-bit RSA key for the CA provides excellent security and should remain secure for 10+ years.
   - 2048-bit RSA keys for hosts provide good security while maintaining broad compatibility.

2. **Modern Elliptic Curve Support**
   - The support for modern ECC curves (P-256, P-384, P-521) provides future-proofing options, as EC certificates:
     - Are more efficient in computation and bandwidth
     - Provide equivalent security with smaller key sizes
     - Generate and validate signatures faster than RSA

3. **Strong Signature Algorithm**
   - SHA-256 is a secure hashing algorithm with no known practical vulnerabilities, appropriate for current and near-future use.

4. **Proper Certificate Extensions**
   - The implementation correctly sets critical extensions:
     - BasicConstraints (CA:TRUE for CAs, CA:FALSE for end-entity certificates)
     - KeyUsage with appropriate flags for each certificate type
   - Includes important non-critical extensions like SubjectAlternativeName and ExtendedKeyUsage

5. **Encrypted Key Storage**
   - The use of password-protected private keys provides an additional security layer

### Considerations and Potential Improvements

1. **RSA vs EC Tradeoffs**
   - While RSA 4096 is very secure, it's computationally expensive and may not be necessary for most homelabs
   - EC keys provide better performance and equivalent security with smaller key sizes
   - Recommendation: Consider making P-384 the default for new CA installations while maintaining RSA compatibility

2. **Signature Algorithm Variety**
   - Current implementation uses SHA-256 for all signatures
   - Recommendation: Consider adding support for SHA-384 for high-security certificates, particularly when paired with EC P-384 or P-521 keys

3. **Certificate Validity Periods**
   - 10-year validity for CA certificates is reasonable for a homelab CA
   - 1-year validity for host certificates follows industry best practices
   - Note: Public CAs now use maximum 398-day validity for TLS certificates, but for a private CA, longer validity periods may be acceptable

4. **Key Protection Mechanism**
   - The `BestAvailableEncryption` is appropriate as it selects the best algorithm available on the system
   - Recommendation: Consider adding an option to specify the encryption algorithm explicitly (AES-256-GCM) for environments where control is required

5. **Browser/Client Compatibility**
   - Current settings are compatible with browsers from the last 3+ years:
     - RSA 2048/4096 + SHA-256: Supported by all modern browsers
     - EC P-256/P-384 + SHA-256: Supported by all browsers from the last 5+ years
   - Recommendation: Add a "compatibility mode" flag for environments requiring support for very old clients (e.g., using SHA-1, though not recommended)

6. **Serial Number Generation**
   - The use of `x509.random_serial_number()` is appropriate for generating random serial numbers
   - Recommendation: Consider adding a sequential component to guarantee uniqueness while maintaining randomness

## Future-proofing Recommendations

1. **Support for Ed25519/Ed448**
   - These Edwards-curve algorithms provide excellent security and performance
   - Ed25519 in particular is gaining widespread adoption
   - Implementation would require extending the `generate_key` function to support these algorithms

2. **Certificate Transparency**
   - Though primarily for public CAs, consider adding optional CT logging capabilities for environments where certificate auditing is important

3. **OCSP and CRL Support**
   - Add support for generating CRLs (Certificate Revocation Lists)
   - Consider implementing a simple OCSP responder for larger deployments

4. **Key Backup Options**
   - Implement secure key backup and recovery mechanisms
   - Consider supporting key escrow for organizational deployments

5. **Advanced CSR Validation**
   - Enhance CSR validation to verify that the request meets policy requirements
   - Add support for custom CSR extensions

## Compatibility Matrix

| Feature | Compatibility with 2-3 Year Old Browsers | Future-proofing Status |
|---------|------------------------------------------|------------------------|
| RSA 2048+ | Excellent | Good (10+ years) |
| EC P-256 | Very Good | Excellent (15+ years) |
| EC P-384 | Very Good | Excellent (20+ years) |
| SHA-256 | Excellent | Good (10+ years) |
| PKCS#8 Format | Excellent | Excellent |
| X.509v3 Extensions | Excellent | Excellent |

## Conclusion

The current implementation of ReactorCA makes excellent choices for a homelab CA, balancing security, compatibility, and ease of use. The default RSA 4096-bit CA keys and 2048-bit host keys with SHA-256 signatures provide strong security while maintaining broad client compatibility.

For environments seeking to maximize future-proofing, the existing EC support offers a path forward, though additional algorithms like Ed25519 would enhance this further. The tool's modular design should make these extensions straightforward to implement.

Overall, ReactorCA is well-positioned for both current use and adaptation to future cryptographic standards while maintaining compatibility with slightly older browsers and systems.