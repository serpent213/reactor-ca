# ReactorCA Security Memorandum

Please use GitHub for vulnerability reports.

## Defaults

Key Generation

- RSA: 2048/3072/4096 bits - Minimum 2048 for current security, 4096 future-proofing against quantum advances
- ECDSA: P-256/P-384/P-521 - NIST-approved curves, P-384 default balances security/performance
- Ed25519: 256-bit - Modern curve with strong security guarantees, immune to many side-channel attacks

Private Key Encryption (age format) (all hard-coded)

- ChaCha20-Poly1305 - Modern authenticated encryption prevents tampering
- scrypt: N=32768, r=8, p=1 - Memory-hard function defeats rainbow tables and ASICs
- Salt: 16 bytes - Prevents rainbow table attacks, standard size for scrypt
- [Age format](https://age-encryption.org/): Battle-tested design and library by Filippo Valsorda, used by major projects

Certificate Validity

- CA: 10 years - Long-lived root minimizes rotation complexity in homelab environments
- Host: 1 year - Short-lived certificates limit exposure window, automated renewal expected
- CSR: 365 days - Matches host certificate policy for consistency

Hashing Algorithms

- CA Default: SHA-384 - Stronger hash for root certificate, matches P-384 curve strength
- Host Default: SHA-256 - Industry standard, adequate for 1-year certificates
- Available: SHA-256/384/512 - Full SHA-2 family support for algorithm agility

Password Security

- Minimum length: 12 characters - NIST 800-63B recommendation for memorized secrets
- Expiry warning: 30/90 days (hard-coded) - Early notification prevents service disruption

## Dependencies

- Go Standard Crypto. We use crypto/x509 for certificate ops, crypto/rsa and crypto/ecdsa for key generation (RSA 2048-4096, ECDSA P-256/384/521, Ed25519), and crypto/rand for secure randomness.

- [filippo.io/age](https://github.com/FiloSottile/age) - Handles password-based private key encryption with ChaCha20-Poly1305 and scrypt.
