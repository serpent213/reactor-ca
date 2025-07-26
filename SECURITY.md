# ReactorCA Security Memorandum

Please use GitHub for vulnerability reports.

## Defaults

Key Generation

- RSA: 2048/3072/4096 bits - Minimum 2048 for current security, 4096 future-proofing against quantum advances
- ECDSA: P-256/P-384/P-521 - NIST-approved curves, P-384 default balances security/performance
- Ed25519: 256-bit - Modern curve with strong security guarantees, immune to many side-channel attacks

Private Key Encryption (age format)

**Password-based encryption** (all parameters hard-coded):
- ChaCha20-Poly1305 - Modern authenticated encryption prevents tampering
- scrypt: N=32768, r=8, p=1 - Memory-hard function defeats rainbow tables and ASICs
- Salt: 16 bytes - Prevents rainbow table attacks, standard size for scrypt

**SSH key-based encryption** (age-ssh):
- Uses existing SSH private keys as age identities for decryption
- SSH public keys serve as age recipients for encryption
- Supports Ed25519, RSA-2048+, and ECDSA P-256/384/521 SSH keys
- Leverages battle-tested SSH key infrastructure and agent integration

**Hardware token encryption** (age plugins):
- Uses age-plugin-* binaries for hardware-backed encryption
- Private keys never leave secure hardware (Secure Enclave, YubiKey, TPM)
- Plugin recipients provide hardware-generated public keys
- Cryptographic operations performed within secure element
- Supports biometric and PIN-based access controls

**Common foundation**:
- [Age format](https://age-encryption.org/): Battle-tested design and library by Filippo Valsorda, used by major projects
- ChaCha20-Poly1305 authenticated encryption in both modes

Certificate Validity

- CA: 10 years - Long-lived root minimizes rotation complexity in homelab environments
- Host: 1 year - Short-lived certificates limit exposure window, automated renewal expected
- CSR: 365 days - Matches host certificate policy for consistency

Hashing Algorithms

- Configuration: Explicit hash algorithm specification required in ca.yaml, hosts inherit from CA if unspecified
- Runtime fallbacks when no hash algorithm configured: RSA keys use SHA-256, ECDSA keys use SHA-384
- Available: SHA-256/384/512 - Full SHA-2 family support for algorithm agility

Signature Algorithms

- RSA: Uses configured hash algorithm, falls back to SHA-256 (SHA256WithRSA/SHA384WithRSA/SHA512WithRSA) - Applied when hash algorithm unspecified or invalid
- ECDSA: Uses configured hash algorithm, falls back to SHA-384 - Applied when hash algorithm unspecified or invalid
- Ed25519: Always PureEd25519 regardless of configuration - Cryptographically fixed, ignores hash algorithm setting

Authentication Security

**Password-based mode**:
- Minimum length: 12 characters - NIST 800-63B recommendation for memorized secrets
- Expiry warning: 30/90 days (hard-coded) - Early notification prevents service disruption

**SSH key-based mode**:
- Relies on SSH key security practices and SSH agent protection
- No additional password requirements beyond SSH key access
- SSH key strength follows standard SSH security recommendations

**Hardware token mode** (age plugins):
- Private keys generated and stored within secure hardware
- Access controlled by hardware security policies (biometrics, PIN, presence)
- Immune to key extraction attacks - cryptographic operations isolated in secure element
- Plugin security depends on underlying hardware token implementation

Memory Protection

**Core dumps**
- Core dumps are disabled on program start

## Dependencies

- Go Standard Crypto. We use crypto/x509 for certificate ops, crypto/rsa and crypto/ecdsa for key generation (RSA 2048-4096, ECDSA P-256/384/521, Ed25519), and crypto/rand for secure randomness.

- [filippo.io/age](https://github.com/FiloSottile/age) - Handles private key encryption with ChaCha20-Poly1305. Supports both password-based (scrypt) and SSH key-based (age-ssh) encryption modes.
