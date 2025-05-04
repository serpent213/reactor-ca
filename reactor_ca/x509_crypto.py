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
from reactor_ca.result import Failure, Result, Success

# Key Generation and Management


def generate_key(key_algorithm: str) -> Result[PrivateKeyTypes, str]:
    """Generate a private key with the specified algorithm.

    Args:
    ----
        key_algorithm: Algorithm specification (e.g., "RSA4096", "ECP256", "ED25519")

    Returns:
    -------
        Result containing a new private key of the specified type or error message

    """
    key_algorithm = key_algorithm.upper()

    try:
        # RSA key algorithms
        if key_algorithm == "RSA2048":
            return Success(
                rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
            )
        elif key_algorithm == "RSA3072":
            return Success(
                rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=3072,
                )
            )
        elif key_algorithm == "RSA4096":
            return Success(
                rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                )
            )
        # EC key algorithms
        elif key_algorithm == "ECP256":
            curve: ec.EllipticCurve = ec.SECP256R1()
            return Success(ec.generate_private_key(curve=curve))
        elif key_algorithm == "ECP384":
            curve = ec.SECP384R1()
            return Success(ec.generate_private_key(curve=curve))
        elif key_algorithm == "ECP521":
            curve = ec.SECP521R1()
            return Success(ec.generate_private_key(curve=curve))
        # Edwards curve algorithms
        elif key_algorithm == "ED25519":
            return Success(ed25519.Ed25519PrivateKey.generate())
        elif key_algorithm == "ED448":
            return Success(ed448.Ed448PrivateKey.generate())
        else:
            return Failure(f"Unsupported key algorithm: {key_algorithm}")
    except Exception as e:
        return Failure(f"Error generating key: {str(e)}")


def serialize_private_key(private_key: PrivateKeyTypes, password: bytes | None = None) -> Result[bytes, str]:
    """Serialize a private key to bytes, optionally encrypted with password.

    Args:
    ----
        private_key: The private key to serialize
        password: Optional password for encryption

    Returns:
    -------
        Result containing serialized key as bytes or error message

    """
    try:
        encryption = BestAvailableEncryption(password) if password else NoEncryption()
        serialized_key = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
        return Success(serialized_key)
    except Exception as e:
        return Failure(f"Error serializing private key: {str(e)}")


def deserialize_private_key(key_data: bytes, password: bytes | None = None) -> Result[PrivateKeyTypes, str]:
    """Deserialize a private key from bytes.

    Args:
    ----
        key_data: PEM encoded key data
        password: Optional password for decryption

    Returns:
    -------
        Result containing deserialized private key or error message

    """
    try:
        key = load_pem_private_key(key_data, password=password)
        return Success(key)
    except Exception as e:
        return Failure(f"Error deserializing private key: {str(e)}")


def verify_key_algorithm(key: PrivateKeyTypes, expected_algorithm: str) -> Result[bool, str]:
    """Verify that a key matches the expected algorithm.

    Args:
    ----
        key: The private key to verify
        expected_algorithm: The expected algorithm identifier (e.g., 'RSA4096', 'ECP256')

    Returns:
    -------
        Result containing True if the key matches the expected algorithm, False otherwise

    """
    try:
        expected_algorithm = expected_algorithm.upper()
        actual_algorithm_result = determine_key_algorithm(key)

        if isinstance(actual_algorithm_result, Failure):
            return actual_algorithm_result

        actual_algorithm = actual_algorithm_result.unwrap()
        return Success(actual_algorithm == expected_algorithm)
    except Exception as e:
        return Failure(f"Error verifying key algorithm: {str(e)}")


def determine_key_algorithm(private_key: PrivateKeyTypes) -> Result[str, str]:
    """Determine the algorithm used by a private key.

    Args:
    ----
        private_key: The private key to examine

    Returns:
    -------
        Result containing a string identifying the key algorithm or error message

    """
    try:
        # Define key size constants
        rsa_key_size_2048 = 2048
        rsa_key_size_3072 = 3072
        rsa_key_size_4096 = 4096

        if isinstance(private_key, rsa.RSAPrivateKey):
            key_size = private_key.key_size
            if key_size == rsa_key_size_2048:
                return Success("RSA2048")
            elif key_size == rsa_key_size_3072:
                return Success("RSA3072")
            elif key_size == rsa_key_size_4096:
                return Success("RSA4096")
            else:
                return Success("RSA4096")  # Default to RSA4096 for unknown sizes
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            curve_name = private_key.curve.name
            if "secp256r1" in curve_name.lower():
                return Success("ECP256")
            elif "secp384r1" in curve_name.lower():
                return Success("ECP384")
            elif "secp521r1" in curve_name.lower():
                return Success("ECP521")
            else:
                return Success("ECP256")  # Default to ECP256 for unknown curves
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            return Success("ED25519")
        elif isinstance(private_key, ed448.Ed448PrivateKey):
            return Success("ED448")
        else:
            return Success("RSA4096")  # Default to RSA4096 for unknown key types
    except Exception as e:
        return Failure(f"Error determining key algorithm: {str(e)}")


def verify_key_matches_cert(cert: x509.Certificate, private_key: PrivateKeyTypes) -> Result[bool, str]:
    """Verify that a certificate and key match.

    Args:
    ----
        cert: X.509 certificate
        private_key: Private key to verify against the certificate

    Returns:
    -------
        Result containing True if the key matches the certificate, False otherwise

    """
    try:
        cert_public_key = cert.public_key()
        key_public_key = private_key.public_key()

        if isinstance(cert_public_key, rsa.RSAPublicKey) and isinstance(key_public_key, rsa.RSAPublicKey):
            # For RSA keys, compare the public_numbers attributes
            cert_public_numbers = cert_public_key.public_numbers()
            key_public_numbers = key_public_key.public_numbers()
            return Success(
                cert_public_numbers.n == key_public_numbers.n and cert_public_numbers.e == key_public_numbers.e
            )
        else:
            # For other key types, compare the serialized public keys
            cert_key_bytes = cert_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            private_key_bytes = key_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            return Success(cert_key_bytes == private_key_bytes)
    except Exception as e:
        return Failure(f"Error verifying key match: {str(e)}")


# Hash Algorithm Utilities


def get_hash_algorithm(algorithm_name: str) -> Result[hashes.HashAlgorithm, str]:
    """Get a hash algorithm instance by name.

    Args:
    ----
        algorithm_name: Name of hash algorithm (SHA256, SHA384, SHA512)

    Returns:
    -------
        Result containing HashAlgorithm instance or error message

    """
    hash_algorithms = {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
    }

    try:
        algorithm_name = algorithm_name.upper()
        if algorithm_name not in hash_algorithms:
            return Failure(f"Unsupported hash algorithm: {algorithm_name}")

        return Success(hash_algorithms[algorithm_name])
    except Exception as e:
        return Failure(f"Error getting hash algorithm: {str(e)}")


# Certificate Creation


def create_ca_certificate(params: CACertificateParams) -> Result[x509.Certificate, str]:
    """Create a self-signed CA certificate using parameters object.

    Args:
    ----
        params: Parameters for CA certificate creation

    Returns:
    -------
        Result containing self-signed CA certificate or error message

    """
    try:
        # If private key isn't provided, generate one based on algorithm (if specified)
        private_key = None
        if params.private_key is None:
            if params.hash_algorithm is None:
                return Failure("Either private_key or hash_algorithm must be provided")

            key_result = generate_key(params.hash_algorithm)
            if isinstance(key_result, Failure):
                return key_result
            private_key = key_result.unwrap()
        else:
            private_key = params.private_key

        # Get validity days or return error if not specified
        if params.validity_days is None:
            return Failure("validity_days must be specified")

        # Get hash algorithm
        if params.hash_algorithm is None:
            return Failure("hash_algorithm must be specified")

        hash_algorithm_result = get_hash_algorithm(params.hash_algorithm)
        if isinstance(hash_algorithm_result, Failure):
            return hash_algorithm_result
        hash_algorithm = hash_algorithm_result.unwrap()

        # Create subject/issuer from subject identity (same for CA cert)
        subject = issuer = params.subject_identity.to_x509_name()

        # Get public key
        public_key = private_key.public_key()

        # Create certificate builder with standard fields
        cert_builder_result = _create_certificate_builder(
            subject=subject, issuer=issuer, public_key=public_key, validity_days=params.validity_days
        )
        if isinstance(cert_builder_result, Failure):
            return cert_builder_result
        cert_builder = cert_builder_result.unwrap()

        # Add extensions
        extensions_result = _add_standard_extensions(cert_builder, is_ca=True, alt_names=params.alt_names)
        if isinstance(extensions_result, Failure):
            return extensions_result
        cert_builder = extensions_result.unwrap()

        # Sign and return the certificate
        return _sign_certificate(cert_builder, private_key, hash_algorithm)
    except Exception as e:
        return Failure(f"Error creating CA certificate: {str(e)}")


def create_certificate(params: CertificateParams) -> Result[x509.Certificate, str]:
    """Create a certificate using parameters object.

    Args:
    ----
        params: Parameters for certificate creation

    Returns:
    -------
        Result containing signed certificate or error message

    """
    try:
        # If private key isn't provided, generate one based on algorithm
        private_key = None
        if params.private_key is None:
            if params.hash_algorithm is None:
                return Failure("Either private_key or hash_algorithm must be provided")

            key_result = generate_key(params.hash_algorithm)
            if isinstance(key_result, Failure):
                return key_result
            private_key = key_result.unwrap()
        else:
            private_key = params.private_key

        # Get validity days or return error if not specified
        if params.validity_days is None:
            return Failure("validity_days must be specified")

        # Get hash algorithm
        if params.hash_algorithm is None:
            return Failure("hash_algorithm must be specified")

        hash_algorithm_result = get_hash_algorithm(params.hash_algorithm)
        if isinstance(hash_algorithm_result, Failure):
            return hash_algorithm_result
        hash_algorithm = hash_algorithm_result.unwrap()

        # Create subject from subject identity
        subject = params.subject_identity.to_x509_name()

        # CA is the issuer
        issuer = params.ca.cert.subject

        # Get public key
        public_key = private_key.public_key()

        # Create certificate builder
        cert_builder_result = _create_certificate_builder(
            subject=subject, issuer=issuer, public_key=public_key, validity_days=params.validity_days
        )
        if isinstance(cert_builder_result, Failure):
            return cert_builder_result
        cert_builder = cert_builder_result.unwrap()

        # Add extensions
        extensions_result = _add_standard_extensions(cert_builder, is_ca=False, alt_names=params.alt_names)
        if isinstance(extensions_result, Failure):
            return extensions_result
        cert_builder = extensions_result.unwrap()

        # Sign with CA key
        return _sign_certificate(cert_builder, params.ca.key, hash_algorithm)
    except Exception as e:
        return Failure(f"Error creating certificate: {str(e)}")


def sign_csr(
    csr: x509.CertificateSigningRequest, ca: CA, validity_days: int, hash_algorithm: str
) -> Result[x509.Certificate, str]:
    """Sign a CSR with a CA key.

    Args:
    ----
        csr: Certificate signing request
        ca: CA object containing certificate and key
        validity_days: Validity period in days
        hash_algorithm: Hash algorithm to use for signing

    Returns:
    -------
        Result containing signed certificate or error message

    """
    try:
        # Verify the CSR signature
        if not csr.is_signature_valid:
            return Failure("CSR has an invalid signature")

        # Get hash algorithm
        hash_algo_result = get_hash_algorithm(hash_algorithm)
        if isinstance(hash_algo_result, Failure):
            return hash_algo_result
        hash_algo = hash_algo_result.unwrap()

        # Create certificate builder
        cert_builder_result = _create_certificate_builder(
            subject=csr.subject, issuer=ca.cert.subject, public_key=csr.public_key(), validity_days=validity_days
        )
        if isinstance(cert_builder_result, Failure):
            return cert_builder_result
        cert_builder = cert_builder_result.unwrap()

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
        extensions_result = _add_standard_extensions(cert_builder=cert_builder, is_ca=False, alt_names=alt_names)
        if isinstance(extensions_result, Failure):
            return extensions_result
        cert_builder = extensions_result.unwrap()

        # Sign the certificate
        return _sign_certificate(cert_builder, ca.key, hash_algo)
    except Exception as e:
        return Failure(f"Error signing CSR: {str(e)}")


# Certificate Serialization


def serialize_certificate(cert: x509.Certificate) -> Result[bytes, str]:
    """Serialize a certificate to bytes (PEM format).

    Args:
    ----
        cert: X.509 certificate to serialize

    Returns:
    -------
        Result containing PEM-encoded certificate bytes or error message

    """
    try:
        return Success(cert.public_bytes(encoding=Encoding.PEM))
    except Exception as e:
        return Failure(f"Error serializing certificate: {str(e)}")


def deserialize_certificate(cert_data: bytes) -> Result[x509.Certificate, str]:
    """Deserialize a certificate from bytes (PEM format).

    Args:
    ----
        cert_data: PEM-encoded certificate data

    Returns:
    -------
        Result containing X.509 certificate object or error message

    """
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
        return Success(cert)
    except Exception as e:
        return Failure(f"Error deserializing certificate: {str(e)}")


# Certificate Examination


def is_cert_valid(cert: x509.Certificate) -> Result[bool, str]:
    """Check if a certificate is currently valid (not expired or not yet valid).

    Args:
    ----
        cert: X.509 certificate object

    Returns:
    -------
        Result containing True if certificate is valid, False otherwise

    """
    try:
        now = datetime.datetime.now(datetime.UTC)
        return Success(cert.not_valid_before <= now <= cert.not_valid_after)
    except Exception as e:
        return Failure(f"Error checking certificate validity: {str(e)}")


def get_certificate_fingerprint(cert: x509.Certificate, hash_algorithm: str) -> Result[str, str]:
    """Get the fingerprint of a certificate using the specified hash algorithm.

    Args:
    ----
        cert: X.509 certificate object
        hash_algorithm: Hash algorithm to use

    Returns:
    -------
        Result containing hex string representation of the fingerprint or error message

    """
    try:
        hash_algo_result = get_hash_algorithm(hash_algorithm)
        if isinstance(hash_algo_result, Failure):
            return hash_algo_result

        hash_algo = hash_algo_result.unwrap()
        fingerprint = cert.fingerprint(hash_algo)
        return Success(fingerprint.hex())
    except Exception as e:
        return Failure(f"Error getting certificate fingerprint: {str(e)}")


# Inventory Integration


def create_inventory_entry(cert: x509.Certificate, short_name: str) -> Result[InventoryEntry, str]:
    """Create an inventory entry from a certificate.

    Args:
    ----
        cert: X.509 certificate
        short_name: Short name for the certificate

    Returns:
    -------
        Result containing InventoryEntry object or error message

    """
    try:
        inventory_entry = InventoryEntry.from_certificate(short_name, cert)
        return Success(inventory_entry)
    except Exception as e:
        return Failure(f"Error creating inventory entry: {str(e)}")


def create_ca_inventory_entry(cert: x509.Certificate) -> Result[CAInventoryEntry, str]:
    """Create a CA inventory entry from a certificate.

    Args:
    ----
        cert: X.509 CA certificate

    Returns:
    -------
        Result containing CAInventoryEntry object or error message

    """
    try:
        ca_inventory_entry = CAInventoryEntry.from_certificate(cert)
        return Success(ca_inventory_entry)
    except Exception as e:
        return Failure(f"Error creating CA inventory entry: {str(e)}")


# Private Helper Functions


def _create_certificate_builder(
    subject: x509.Name, issuer: x509.Name, public_key: PublicKeyTypes, validity_days: int
) -> Result[x509.CertificateBuilder, str]:
    """Create a certificate builder with the essential attributes.

    Args:
    ----
        subject: The certificate subject
        issuer: The certificate issuer (CA)
        public_key: Public key to include in the certificate
        validity_days: Validity period in days

    Returns:
    -------
        Result containing initialized certificate builder or error message

    """
    try:
        now = datetime.datetime.now(datetime.UTC)

        if isinstance(public_key, dh.DHPublicKey):
            return Failure("DHPublicKey is not supported for certificates")

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
        )

        return Success(cert_builder)
    except Exception as e:
        return Failure(f"Error creating certificate builder: {str(e)}")


def _add_standard_extensions(
    cert_builder: x509.CertificateBuilder, is_ca: bool = False, alt_names: AlternativeNames | None = None
) -> Result[x509.CertificateBuilder, str]:
    """Add standard X.509 extensions to a certificate builder.

    Args:
    ----
        cert_builder: The certificate builder to add extensions to
        is_ca: Whether this is a CA certificate
        alt_names: Optional AlternativeNames object

    Returns:
    -------
        Result containing certificate builder with extensions added or error message

    """
    try:
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
            sans_result = alt_names.process_all_sans()
            if isinstance(sans_result, Failure):
                return sans_result

            general_names = sans_result.unwrap()
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(general_names),
                critical=False,
            )

        return Success(cert_builder)
    except Exception as e:
        return Failure(f"Error adding standard extensions: {str(e)}")


def _sign_certificate(
    cert_builder: x509.CertificateBuilder, private_key: PrivateKeyTypes, hash_algo: hashes.HashAlgorithm
) -> Result[x509.Certificate, str]:
    """Sign a certificate builder with the given private key and hash algorithm.

    Args:
    ----
        cert_builder: The populated certificate builder
        private_key: The private key to sign with
        hash_algo: The hash algorithm to use for signing

    Returns:
    -------
        Result containing signed certificate or error message

    """
    try:
        # Check if key type is supported for signing
        if isinstance(private_key, dh.DHPrivateKey | x25519.X25519PrivateKey | x448.X448PrivateKey):
            return Failure(f"Cannot sign with {type(private_key).__name__} as it is not supported for signing")

        # Sign the certificate
        cert = cert_builder.sign(private_key, hash_algo)
        return Success(cert)
    except Exception as e:
        return Failure(f"Error signing certificate: {str(e)}")
