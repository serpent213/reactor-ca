# X509 Crypto Module Refactoring Plan

## Design Principles

1. **Pure Cryptographic Functions**
   - x509_crypto should NEVER deal with files, only with binary data
   - Functions should be pure, taking inputs and returning outputs without side effects
   - No UI/console output from crypto functions

2. **Model-Centric Design** 
   - Make full use of the models we have (CertificateParams, CACertificateParams, etc.)
   - Any model transformations belong in models.py
   - Define clear boundaries between models and crypto operations

3. **Clean Interface**
   - Don't maintain compatibility with existing code
   - Design as if starting from scratch
   - Create a cohesive and consistent API

## Proposed Interface for x509_crypto.py

```python
"""
reactor_ca.x509_crypto

This module provides cryptographic operations for X.509 certificate generation, 
manipulation, and validation without any file handling or UI interactions.
"""

### Key Generation and Management ###

def generate_key(key_algorithm: str) -> PrivateKeyTypes:
    """Generate a private key with the specified algorithm.
    
    Args:
        key_algorithm: Algorithm specification (e.g., "RSA4096", "ECP256", "ED25519")
        
    Returns:
        A new private key of the specified type
    """

def serialize_private_key(private_key: PrivateKeyTypes, password: bytes | None = None) -> bytes:
    """Serialize a private key to bytes, optionally encrypted with password."""

def deserialize_private_key(key_data: bytes, password: bytes | None = None) -> PrivateKeyTypes:
    """Deserialize a private key from bytes."""

def verify_key_algorithm(key: PrivateKeyTypes, expected_algorithm: str) -> bool:
    """Verify that a key matches the expected algorithm."""
    
def determine_key_algorithm(private_key: PrivateKeyTypes) -> str:
    """Determine the algorithm used by a private key."""
    
def verify_key_matches_cert(cert: x509.Certificate, private_key: PrivateKeyTypes) -> bool:
    """Verify that a certificate and key match."""

### Hash Algorithm Utilities ###

def get_hash_algorithm(algorithm_name: str | None = None) -> hashes.HashAlgorithm:
    """Get a hash algorithm instance by name."""

### Certificate Creation ###

def create_certificate(params: CertificateParams) -> x509.Certificate:
    """Create a certificate using parameters object.
    
    This is the primary function for creating host certificates. It extracts all
    necessary information from the CertificateParams model.
    """

def create_ca_certificate(params: CACertificateParams) -> x509.Certificate:
    """Create a self-signed CA certificate using parameters object.
    
    This is the primary function for creating CA certificates. It extracts all
    necessary information from the CACertificateParams model.
    """

def sign_csr(
    csr: x509.CertificateSigningRequest,
    ca: CA,
    validity_days: int,
    hash_algorithm: hashes.HashAlgorithm | None = None
) -> x509.Certificate:
    """Sign a CSR with a CA key."""

### Certificate Serialization ###

def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to bytes (PEM format)."""

def deserialize_certificate(cert_data: bytes) -> x509.Certificate:
    """Deserialize a certificate from bytes (PEM format)."""

### Certificate Examination ###

def is_cert_valid(cert: x509.Certificate) -> bool:
    """Check if a certificate is currently valid (not expired or not yet valid)."""

def get_certificate_fingerprint(
    cert: x509.Certificate, 
    hash_algorithm: hashes.HashAlgorithm | None = None
) -> str:
    """Get the fingerprint of a certificate using the specified hash algorithm."""

### Inventory Integration ###

def create_inventory_entry(cert: x509.Certificate, short_name: str) -> InventoryEntry:
    """Create an inventory entry from a certificate."""

def create_ca_inventory_entry(cert: x509.Certificate) -> CAInventoryEntry:
    """Create a CA inventory entry from a certificate."""
```

## Implementation Strategy

1. **Leverage Enhanced Models**
   - The updated models with factory methods (`from_ca_config`, `from_host_config`) enable clean separation of concerns
   - Models handle data transformation and parameter defaulting
   - Crypto operations focus purely on cryptographic functionality

2. **Private Implementation Details**
   - Move helper functions to private scope with underscore prefix
   - Simplify the public API to focus on the core certificate creation functions

3. **Binary Data Instead of Files**
   - Replace file operations with serialization/deserialization functions
   - File I/O handled by calling code, not crypto module

## Internal Helper Functions

The following functions should exist in x509_crypto.py but be considered private implementation details:

```python
def _create_certificate_builder(
    subject: x509.Name, 
    issuer: x509.Name, 
    public_key: PublicKeyTypes, 
    validity_days: int = 365
) -> x509.CertificateBuilder:
    """Create a certificate builder with essential attributes."""

def _add_standard_extensions(
    cert_builder: x509.CertificateBuilder, 
    is_ca: bool = False, 
    alt_names: AlternativeNames | None = None
) -> x509.CertificateBuilder:
    """Add standard X.509 extensions to a certificate builder."""

def _sign_certificate(
    cert_builder: x509.CertificateBuilder, 
    private_key: PrivateKeyTypes, 
    hash_algo: hashes.HashAlgorithm
) -> x509.Certificate:
    """Sign a certificate builder with the given private key and hash algorithm."""
```

## Usage Examples with Updated Models

### Creating a CA Certificate

```python
# Create CACertificateParams directly
ca_params = CACertificateParams(
    subject_identity=SubjectIdentity(
        common_name="My Certificate Authority",
        organization="My Organization",
        organization_unit="IT",
        country="US",
        state="Washington",
        locality="Seattle",
        email="admin@example.com",
    ),
    hash_algorithm="SHA256",
    validity_days=3650,  # 10 years
)

# Or create from a CAConfig object
ca_params = CACertificateParams.from_ca_config(ca_config)

# Generate the certificate (will generate a key if none provided)
ca_cert = create_ca_certificate(ca_params)
```

### Creating a Host Certificate

```python
# Create CertificateParams directly
cert_params = CertificateParams(
    subject_identity=SubjectIdentity(common_name="www.example.com"),
    ca=ca,  # CA object containing cert, key and config
    alt_names=AlternativeNames(dns=["www.example.com", "example.com"]),
    validity_days=365,
    hash_algorithm="SHA256",
)

# Or create from a HostConfig object
cert_params = CertificateParams.from_host_config(
    host_config=host_config,
    ca=ca,
)

# Generate the certificate (will generate a key if none provided)
host_cert = create_certificate(cert_params)
```

## Benefits

1. **Clear Separation of Concerns**
   - Models handle data representation and transformation
   - Crypto module handles pure cryptographic operations
   - No mixing of file I/O with crypto operations

2. **Simplified Interface**
   - Two primary certificate creation functions with clear purposes
   - Consistent parameter passing via well-defined data models
   - Improved testability with pure functions

3. **Type Safety**
   - Better use of types through dataclasses
   - Clearer function signatures
   - More predictable behavior

4. **Reduced Duplication**
   - Common code for CA and host certificates unified
   - Parameter handling standardized through models
   - Single source of truth for certificate creation logic