"""X.509 and cryptographic utility functions for ReactorCA.

This module provides cryptographic operations for certificate generation,
manipulation, and validation without any file handling or UI interactions.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from reactor_ca.models import (
    CA,
    AlternativeNames,
    CACertificateParams,
    CAInventoryEntry,
    CertificateParams,
    InventoryEntry,
)

# Key Generation and Management


def generate_key(key_algorithm: str) -> PrivateKeyTypes:
    """Generate a private key with the specified algorithm.

    Args:
    ----
        key_algorithm: Algorithm specification (e.g., "RSA4096", "ECP256", "ED25519")

    Returns:
    -------
        A new private key of the specified type

    """
    key_algorithm = key_algorithm.upper()

    # RSA key algorithms
    if key_algorithm == "RSA2048":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_algorithm == "RSA3072":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    elif key_algorithm == "RSA4096":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
    # EC key algorithms
    elif key_algorithm == "ECP256":
        curve: ec.EllipticCurve = ec.SECP256R1()
        return ec.generate_private_key(curve=curve)
    elif key_algorithm == "ECP384":
        curve = ec.SECP384R1()
        return ec.generate_private_key(curve=curve)
    elif key_algorithm == "ECP521":
        curve = ec.SECP521R1()
        return ec.generate_private_key(curve=curve)
    # Edwards curve algorithms
    elif key_algorithm == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()
    elif key_algorithm == "ED448":
        return ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported key algorithm: {key_algorithm}")


def serialize_private_key(private_key: PrivateKeyTypes, password: bytes | None = None) -> bytes:
    """Serialize a private key to bytes, optionally encrypted with password.

    Args:
    ----
        private_key: The private key to serialize
        password: Optional password for encryption

    Returns:
    -------
        Serialized key as bytes

    """
    encryption = BestAvailableEncryption(password) if password else NoEncryption()
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)


def deserialize_private_key(key_data: bytes, password: bytes | None = None) -> PrivateKeyTypes:
    """Deserialize a private key from bytes.

    Args:
    ----
        key_data: PEM encoded key data
        password: Optional password for decryption

    Returns:
    -------
        Deserialized private key

    """
    return load_pem_private_key(key_data, password=password)


def verify_key_algorithm(key: PrivateKeyTypes, expected_algorithm: str) -> bool:
    """Verify that a key matches the expected algorithm.

    Args:
    ----
        key: The private key to verify
        expected_algorithm: The expected algorithm identifier (e.g., 'RSA4096', 'ECP256')

    Returns:
    -------
        True if the key matches the expected algorithm, False otherwise

    """
    expected_algorithm = expected_algorithm.upper()
    actual_algorithm = determine_key_algorithm(key)
    return actual_algorithm == expected_algorithm


def determine_key_algorithm(private_key: PrivateKeyTypes) -> str:
    """Determine the algorithm used by a private key.

    Args:
    ----
        private_key: The private key to examine

    Returns:
    -------
        A string identifying the key algorithm

    """
    # Define key size constants
    rsa_key_size_2048 = 2048
    rsa_key_size_3072 = 3072
    rsa_key_size_4096 = 4096

    if isinstance(private_key, rsa.RSAPrivateKey):
        key_size = private_key.key_size
        if key_size == rsa_key_size_2048:
            return "RSA2048"
        elif key_size == rsa_key_size_3072:
            return "RSA3072"
        elif key_size == rsa_key_size_4096:
            return "RSA4096"
        else:
            return "RSA4096"  # Default to RSA4096 for unknown sizes
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = private_key.curve.name
        if "secp256r1" in curve_name.lower():
            return "ECP256"
        elif "secp384r1" in curve_name.lower():
            return "ECP384"
        elif "secp521r1" in curve_name.lower():
            return "ECP521"
        else:
            return "ECP256"  # Default to ECP256 for unknown curves
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        return "ED25519"
    elif isinstance(private_key, ed448.Ed448PrivateKey):
        return "ED448"
    else:
        return "RSA4096"  # Default to RSA4096 for unknown key types


def verify_key_matches_cert(cert: x509.Certificate, private_key: PrivateKeyTypes) -> bool:
    """Verify that a certificate and key match.

    Args:
    ----
        cert: X.509 certificate
        private_key: Private key to verify against the certificate

    Returns:
    -------
        True if the key matches the certificate, False otherwise

    """
    cert_public_key = cert.public_key()
    key_public_key = private_key.public_key()

    if isinstance(cert_public_key, rsa.RSAPublicKey) and isinstance(key_public_key, rsa.RSAPublicKey):
        # For RSA keys, compare the public_numbers attributes
        cert_public_numbers = cert_public_key.public_numbers()
        key_public_numbers = key_public_key.public_numbers()
        return cert_public_numbers.n == key_public_numbers.n and cert_public_numbers.e == key_public_numbers.e
    else:
        # For other key types, compare the serialized public keys
        return cert_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ) == key_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


# Hash Algorithm Utilities


def get_hash_algorithm(algorithm_name: str) -> hashes.HashAlgorithm:
    """Get a hash algorithm instance by name.

    Args:
    ----
        algorithm_name: Name of hash algorithm (SHA256, SHA384, SHA512)

    Returns:
    -------
        HashAlgorithm instance

    Raises:
    ------
        ValueError: If an unsupported algorithm is specified

    """
    hash_algorithms = {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
    }

    algorithm_name = algorithm_name.upper()
    if algorithm_name not in hash_algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm_name}")

    return hash_algorithms[algorithm_name]


# Certificate Creation


def create_ca_certificate(params: CACertificateParams) -> x509.Certificate:
    """Create a self-signed CA certificate using parameters object.

    Args:
    ----
        params: Parameters for CA certificate creation

    Returns:
    -------
        Self-signed CA certificate

    Raises:
    ------
        ValueError: If params.private_key is None and key generation fails

    """
    # If private key isn't provided, generate one based on algorithm (if specified)
    if params.private_key is None:
        if params.hash_algorithm is None:
            raise ValueError("Either private_key or hash_algorithm must be provided")
        private_key = generate_key(params.hash_algorithm)
    else:
        private_key = params.private_key

    # Get validity days or raise error if not specified
    if params.validity_days is None:
        raise ValueError("validity_days must be specified")

    # Get hash algorithm
    if params.hash_algorithm is None:
        raise ValueError("hash_algorithm must be specified")
    hash_algorithm = get_hash_algorithm(params.hash_algorithm)

    # Create subject/issuer from subject identity (same for CA cert)
    subject = issuer = params.subject_identity.to_x509_name()

    # Get public key
    public_key = private_key.public_key()

    # Create certificate builder with standard fields
    cert_builder = _create_certificate_builder(
        subject=subject, issuer=issuer, public_key=public_key, validity_days=params.validity_days
    )

    # Add extensions
    cert_builder = _add_standard_extensions(cert_builder, is_ca=True, alt_names=params.alt_names)

    # Sign and return the certificate
    return _sign_certificate(cert_builder, private_key, hash_algorithm)


def create_certificate(params: CertificateParams) -> x509.Certificate:
    """Create a certificate using parameters object.

    Args:
    ----
        params: Parameters for certificate creation

    Returns:
    -------
        Signed certificate

    Raises:
    ------
        ValueError: If required parameters are missing

    """
    # If private key isn't provided, generate one based on algorithm
    if params.private_key is None:
        if params.hash_algorithm is None:
            raise ValueError("Either private_key or hash_algorithm must be provided")
        private_key = generate_key(params.hash_algorithm)
    else:
        private_key = params.private_key

    # Get validity days or raise error if not specified
    if params.validity_days is None:
        raise ValueError("validity_days must be specified")

    # Get hash algorithm
    if params.hash_algorithm is None:
        raise ValueError("hash_algorithm must be specified")
    hash_algorithm = get_hash_algorithm(params.hash_algorithm)

    # Create subject from subject identity
    subject = params.subject_identity.to_x509_name()

    # CA is the issuer
    issuer = params.ca.cert.subject

    # Get public key
    public_key = private_key.public_key()

    # Create certificate builder
    cert_builder = _create_certificate_builder(
        subject=subject, issuer=issuer, public_key=public_key, validity_days=params.validity_days
    )

    # Add extensions
    cert_builder = _add_standard_extensions(cert_builder, is_ca=False, alt_names=params.alt_names)

    # Sign with CA key
    return _sign_certificate(cert_builder, params.ca.key, hash_algorithm)


def sign_csr(
    csr: x509.CertificateSigningRequest, ca: CA, validity_days: int, hash_algorithm: str
) -> x509.Certificate:
    """Sign a CSR with a CA key.

    Args:
    ----
        csr: Certificate signing request
        ca: CA object containing certificate and key
        validity_days: Validity period in days
        hash_algorithm: Hash algorithm to use for signing

    Returns:
    -------
        Signed certificate

    Raises:
    ------
        ValueError: If CSR is invalid or parameters are missing

    """
    # Verify the CSR signature
    if not csr.is_signature_valid:
        raise ValueError("CSR has an invalid signature")

    # Get hash algorithm
    hash_algo = get_hash_algorithm(hash_algorithm)

    # Create certificate builder
    cert_builder = _create_certificate_builder(
        subject=csr.subject, issuer=ca.cert.subject, public_key=csr.public_key(), validity_days=validity_days
    )

    # Extract SANs from CSR if present
    alt_names = None
    for ext in csr.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            # Convert to our AlternativeNames model
            san_list = []
            for san in ext.value:
                san_list.append(san)

            # Create an empty AlternativeNames object to pass to _add_standard_extensions
            # The san_list will be passed directly
            alt_names = AlternativeNames()
            break

    # Add standard extensions
    cert_builder = _add_standard_extensions(cert_builder=cert_builder, is_ca=False, alt_names=alt_names)

    # Sign the certificate
    return _sign_certificate(cert_builder, ca.key, hash_algo)


# Certificate Serialization


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to bytes (PEM format).

    Args:
    ----
        cert: X.509 certificate to serialize

    Returns:
    -------
        PEM-encoded certificate bytes

    """
    return cert.public_bytes(encoding=Encoding.PEM)


def deserialize_certificate(cert_data: bytes) -> x509.Certificate:
    """Deserialize a certificate from bytes (PEM format).

    Args:
    ----
        cert_data: PEM-encoded certificate data

    Returns:
    -------
        X.509 certificate object

    Raises:
    ------
        ValueError: If certificate data is invalid

    """
    return x509.load_pem_x509_certificate(cert_data)


# Certificate Examination


def is_cert_valid(cert: x509.Certificate) -> bool:
    """Check if a certificate is currently valid (not expired or not yet valid).

    Args:
    ----
        cert: X.509 certificate object

    Returns:
    -------
        True if certificate is valid, False otherwise

    """
    now = datetime.datetime.now(datetime.UTC)
    return cert.not_valid_before <= now <= cert.not_valid_after


def get_certificate_fingerprint(cert: x509.Certificate, hash_algorithm: str) -> str:
    """Get the fingerprint of a certificate using the specified hash algorithm.

    Args:
    ----
        cert: X.509 certificate object
        hash_algorithm: Hash algorithm to use

    Returns:
    -------
        Hex string representation of the fingerprint

    """
    hash_algo = get_hash_algorithm(hash_algorithm)
    fingerprint = cert.fingerprint(hash_algo)
    return fingerprint.hex()


# Inventory Integration


def create_inventory_entry(cert: x509.Certificate, short_name: str) -> InventoryEntry:
    """Create an inventory entry from a certificate.

    Args:
    ----
        cert: X.509 certificate
        short_name: Short name for the certificate

    Returns:
    -------
        InventoryEntry object

    """
    return InventoryEntry.from_certificate(short_name, cert)


def create_ca_inventory_entry(cert: x509.Certificate) -> CAInventoryEntry:
    """Create a CA inventory entry from a certificate.

    Args:
    ----
        cert: X.509 CA certificate

    Returns:
    -------
        CAInventoryEntry object

    """
    return CAInventoryEntry.from_certificate(cert)


# Private Helper Functions


def _create_certificate_builder(
    subject: x509.Name, issuer: x509.Name, public_key: PublicKeyTypes, validity_days: int
) -> x509.CertificateBuilder:
    """Create a certificate builder with the essential attributes.

    Args:
    ----
        subject: The certificate subject
        issuer: The certificate issuer (CA)
        public_key: Public key to include in the certificate
        validity_days: Validity period in days

    Returns:
    -------
        Initialized certificate builder

    Raises:
    ------
        ValueError: If an unsupported public key type is provided

    """
    now = datetime.datetime.now(datetime.UTC)

    if isinstance(public_key, dh.DHPublicKey):
        raise ValueError("DHPublicKey is not supported for certificates")

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )


def _add_standard_extensions(
    cert_builder: x509.CertificateBuilder, is_ca: bool = False, alt_names: AlternativeNames | None = None
) -> x509.CertificateBuilder:
    """Add standard X.509 extensions to a certificate builder.

    Args:
    ----
        cert_builder: The certificate builder to add extensions to
        is_ca: Whether this is a CA certificate
        alt_names: Optional AlternativeNames object

    Returns:
    -------
        Certificate builder with extensions added

    """
    # Add BasicConstraints
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True,
    )

    # Add KeyUsage - different for CA vs server/client certs
    if is_ca:
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # For non-CA certs, add ExtendedKeyUsage
    if not is_ca:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )

    # Add Subject Alternative Names if provided
    if alt_names and not alt_names.is_empty():
        general_names = alt_names.process_all_sans()
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )

    return cert_builder


def _sign_certificate(
    cert_builder: x509.CertificateBuilder, private_key: PrivateKeyTypes, hash_algo: hashes.HashAlgorithm
) -> x509.Certificate:
    """Sign a certificate builder with the given private key and hash algorithm.

    Args:
    ----
        cert_builder: The populated certificate builder
        private_key: The private key to sign with
        hash_algo: The hash algorithm to use for signing

    Returns:
    -------
        Signed certificate

    Raises:
    ------
        ValueError: If an unsupported key type is provided

    """
    # Check if key type is supported for signing
    if isinstance(private_key, dh.DHPrivateKey | x25519.X25519PrivateKey | x448.X448PrivateKey):
        raise ValueError(f"Cannot sign with {type(private_key).__name__} as it is not supported for signing")

    # Sign the certificate
    return cert_builder.sign(private_key, hash_algo)
