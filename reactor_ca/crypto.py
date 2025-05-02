"""Cryptographic utility functions for ReactorCA.

This module provides cryptographic operations for certificate generation,
manipulation, and validation.
"""

import datetime
import ipaddress
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509.general_name import (
    DirectoryName,
    OtherName,
    RegisteredID,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID
from rich.console import Console

from reactor_ca.models import (
    AlternativeNames,
    CAConfig,
    HostConfig,
    SubjectIdentity,
    ValidityConfig,
)

console = Console()


def get_certificate_metadata(cert: x509.Certificate) -> SubjectIdentity:
    """Extract common metadata fields from a certificate.

    Args:
    ----
        cert: The certificate to extract metadata from

    Returns:
    -------
        SubjectIdentity with common certificate metadata fields

    """
    return SubjectIdentity.from_x509_name(cert.subject)


def create_subject_name(subject_identity: SubjectIdentity) -> x509.Name:
    """Create a certificate subject name from a SubjectIdentity.

    Args:
    ----
        subject_identity: Subject identity information

    Returns:
    -------
        x509.Name object with the provided attributes

    """
    return subject_identity.to_x509_name()


def create_subject_from_config(
    hostname: str, ca_config: CAConfig, host_config: HostConfig | None = None
) -> x509.Name:
    """Create a certificate subject from CA config and optional host config.

    Args:
    ----
        hostname: The hostname to use as common name
        ca_config: The CA configuration containing default values
        host_config: Optional host configuration that can override CA defaults

    Returns:
    -------
        x509.Name object with the configured attributes

    """
    # Create a SubjectIdentity with fields from host_config (if available) or from CA config
    subject = SubjectIdentity(
        common_name=hostname,
        organization=host_config.organization if host_config and host_config.organization else ca_config.organization,
        organization_unit=host_config.organization_unit
        if host_config and host_config.organization_unit
        else ca_config.organization_unit,
        country=host_config.country if host_config and host_config.country else ca_config.country,
        state=host_config.state if host_config and host_config.state else ca_config.state,
        locality=host_config.locality if host_config and host_config.locality else ca_config.locality,
        email=host_config.email if host_config and host_config.email else ca_config.email,
    )

    return subject.to_x509_name()


def create_certificate_builder(
    subject: x509.Name, issuer: x509.Name, public_key: PublicKeyTypes, validity_days: int = 365
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

    """
    now = datetime.datetime.now(datetime.UTC)

    # DHPublicKey is not supported by certificate builder, so we need to check for it
    from cryptography.hazmat.primitives.asymmetric import dh

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


def add_standard_extensions(
    cert_builder: x509.CertificateBuilder, is_ca: bool = False, san_list: list[Any] | None = None
) -> x509.CertificateBuilder:
    """Add standard X.509 extensions to a certificate builder.

    Args:
    ----
        cert_builder: The certificate builder to add extensions to
        is_ca: Whether this is a CA certificate
        san_list: Optional list of Subject Alternative Names

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
    if san_list and len(san_list) > 0:
        from cryptography.x509 import GeneralName

        # Cast to the type that SubjectAlternativeName expects
        general_names = cast(list[GeneralName], san_list)

        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )

    return cert_builder


def sign_certificate(
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

    """
    # Validate the hash algorithm is one of the supported types
    valid_hash_types = (
        hashes.SHA224,
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
        hashes.SHA3_224,
        hashes.SHA3_256,
        hashes.SHA3_384,
        hashes.SHA3_512,
    )
    assert isinstance(hash_algo, valid_hash_types), "Unsupported hash algorithm"

    # Sign the certificate
    # We need to specifically exclude DHPrivateKey and X25519/X448PrivateKey from the sign method
    # because the cryptography library doesn't support signing with these keys
    from cryptography.hazmat.primitives.asymmetric import dh, x448, x25519

    if isinstance(private_key, dh.DHPrivateKey | x25519.X25519PrivateKey | x448.X448PrivateKey):
        raise ValueError(f"Cannot sign with {type(private_key).__name__} as it is not supported for signing")
    return cert_builder.sign(private_key, hash_algo)


def process_dns_names(names: list[str]) -> list[x509.DNSName]:
    """Process DNS names into appropriate SAN format.

    Args:
    ----
        names: List of DNS name strings

    Returns:
    -------
        List of x509.DNSName objects

    """
    return [x509.DNSName(name) for name in names]


def process_ip_addresses(ips: list[str]) -> list[x509.IPAddress]:
    """Process IP addresses into appropriate SAN format.

    Args:
    ----
        ips: List of IP address strings

    Returns:
    -------
        List of valid x509.IPAddress objects

    """
    result = []

    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            result.append(x509.IPAddress(ip_obj))
        except ValueError:
            console.print(f"[yellow]Warning:[/yellow] Invalid IP address {ip}, skipping")

    return result


def process_email_addresses(emails: list[str]) -> list[x509.RFC822Name]:
    """Process email addresses into appropriate SAN format.

    Args:
    ----
        emails: List of email address strings

    Returns:
    -------
        List of valid x509.RFC822Name objects

    """
    result = []

    for email in emails:
        # Simple email validation
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            result.append(x509.RFC822Name(email))
        else:
            console.print(f"[yellow]Warning:[/yellow] Invalid email address {email}, skipping")

    return result


def process_uri_addresses(uris: list[str]) -> list[x509.UniformResourceIdentifier]:
    """Process URIs into appropriate SAN format.

    Args:
    ----
        uris: List of URI strings

    Returns:
    -------
        List of valid x509.UniformResourceIdentifier objects

    """
    result = []

    for uri in uris:
        try:
            # Validate URI
            parsed = urlparse(uri)
            if parsed.scheme and parsed.netloc:
                result.append(UniformResourceIdentifier(uri))
            else:
                raise ValueError("Invalid URI format")
        except Exception:
            console.print(f"[yellow]Warning:[/yellow] Invalid URI {uri}, skipping")

    return result


def process_directory_names(dns: list[str]) -> list[x509.DirectoryName]:
    """Process directory names into appropriate SAN format.

    Args:
    ----
        dns: List of directory name strings (format "CN=example,O=org,C=US")

    Returns:
    -------
        List of valid x509.DirectoryName objects

    """
    result = []

    for dn in dns:
        try:
            # Expect format like "CN=example,O=org,C=US"
            attrs = []
            for part in dn.split(","):
                if "=" in part:
                    attr_type, value = part.strip().split("=", 1)
                    attr_type = attr_type.upper()

                    if attr_type == "CN":
                        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
                    elif attr_type == "O":
                        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
                    elif attr_type == "OU":
                        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
                    elif attr_type == "C":
                        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
                    elif attr_type == "ST":
                        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
                    elif attr_type == "L":
                        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
                    elif attr_type == "E":
                        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, value))

            if attrs:
                # Convert x509.Name to the correct type for DirectoryName
                name = x509.Name(attrs)
                # Using proper typing for DirectoryName that accepts x509.Name
                result.append(DirectoryName(name))
            else:
                raise ValueError("No valid attributes found")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid directory name {dn}: {str(e)}, skipping")

    return result


def process_registered_ids(oids: list[str]) -> list[x509.RegisteredID]:
    """Process OID strings into appropriate SAN format.

    Args:
    ----
        oids: List of OID strings

    Returns:
    -------
        List of valid x509.RegisteredID objects

    """
    from cryptography.x509 import ObjectIdentifier

    result = []

    for oid in oids:
        try:
            # Validate OID format
            if re.match(r"^\d+(\.\d+)*$", oid):
                result.append(RegisteredID(ObjectIdentifier(oid)))
            else:
                raise ValueError("Invalid OID format")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid OID {oid}: {str(e)}, skipping")

    return result


def process_other_names(other_names: list[str]) -> list[x509.OtherName]:
    """Process other name strings into appropriate SAN format.

    Args:
    ----
        other_names: List of other name strings (format "oid:value")

    Returns:
    -------
        List of valid x509.OtherName objects

    """
    from cryptography.x509 import ObjectIdentifier

    result = []

    for other_name in other_names:
        try:
            # Format expected: "oid:value"
            if ":" in other_name:
                oid_str, value = other_name.split(":", 1)
                oid_str = oid_str.strip()
                value = value.strip()

                # Validate OID format
                if re.match(r"^\d+(\.\d+)*$", oid_str):
                    oid_obj = ObjectIdentifier(oid_str)
                    # Encode value as bytes
                    value_bytes = value.encode("utf-8")
                    result.append(OtherName(oid_obj, value_bytes))
                else:
                    raise ValueError("Invalid OID format")
            else:
                raise ValueError("Invalid format, expected 'oid:value'")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid other name {other_name}: {str(e)}, skipping")

    return result


def process_all_sans(alt_names: AlternativeNames) -> list[Any]:
    """Process all Subject Alternative Name types.

    Args:
    ----
        alt_names: AlternativeNames object containing SAN values

    Returns:
    -------
        List of all valid SAN objects

    """
    from cryptography.x509 import GeneralName

    # Initialize the result list
    result: list[GeneralName] = []

    # Add DNS names
    if alt_names.dns:
        dns_names = process_dns_names(alt_names.dns)
        # All items in dns_names are GeneralName subtypes which can be safely added
        result.extend(cast(list[GeneralName], dns_names))

    # Add IP addresses
    if alt_names.ip:
        ip_addresses = process_ip_addresses(alt_names.ip)
        result.extend(cast(list[GeneralName], ip_addresses))

    # Add email addresses
    if alt_names.email:
        email_addresses = process_email_addresses(alt_names.email)
        result.extend(cast(list[GeneralName], email_addresses))

    # Add URIs
    if alt_names.uri:
        uris = process_uri_addresses(alt_names.uri)
        result.extend(cast(list[GeneralName], uris))

    # Add directory names
    if alt_names.directory_name:
        directory_names = process_directory_names(alt_names.directory_name)
        result.extend(cast(list[GeneralName], directory_names))

    # Add registered IDs (OIDs)
    if alt_names.registered_id:
        registered_ids = process_registered_ids(alt_names.registered_id)
        result.extend(cast(list[GeneralName], registered_ids))

    # Add other names
    if alt_names.other_name:
        other_names = process_other_names(alt_names.other_name)
        result.extend(cast(list[GeneralName], other_names))

    return result


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


def get_certificate_fingerprint(cert: x509.Certificate, hash_algorithm: hashes.HashAlgorithm | None = None) -> str:
    """Get the fingerprint of a certificate using the specified hash algorithm.

    Args:
    ----
        cert: X.509 certificate object
        hash_algorithm: Hash algorithm to use

    Returns:
    -------
        Hex string representation of the fingerprint

    """
    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()
    fingerprint = cert.fingerprint(hash_algorithm)
    return fingerprint.hex()


def is_cert_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
    """Check if a certificate has been revoked according to a CRL.

    Args:
    ----
        cert: X.509 certificate object
        crl: CertificateRevocationList object

    Returns:
    -------
        True if certificate is revoked, False otherwise

    """
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            return True
    return False


def load_certificate(cert_path: Path) -> x509.Certificate:
    """Load a certificate from a file.

    Args:
    ----
        cert_path: Path to the certificate file

    Returns:
    -------
        x509.Certificate object

    Raises:
    ------
        FileNotFoundError: If certificate file doesn't exist
        ValueError: If file cannot be parsed as a certificate

    """
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")

    with open(cert_path, "rb") as f:
        cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data)


def save_private_key(private_key: PrivateKeyTypes, key_path: Path, password: bytes | None = None) -> None:
    """Save a private key to a file with encryption if password provided.

    Args:
    ----
        private_key: The private key to save
        key_path: Path where to save the key
        password: Optional password for encryption

    """
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    # Ensure parent directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Encrypt with password if provided
    encryption = BestAvailableEncryption(password) if password else NoEncryption()
    key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

    # Write to file
    with open(key_path, "wb") as f:
        f.write(key_bytes)


def calculate_validity_days(validity_config: "ValidityConfig") -> int:
    """Calculate validity days based on configuration.

    Args:
    ----
        validity_config: ValidityConfig object with days and/or years

    Returns:
    -------
        Total number of days for validity period

    """
    # If days is explicitly set, use it
    if validity_config.days is not None:
        return validity_config.days

    # If years is set, convert to days
    if validity_config.years is not None:
        return validity_config.years * 365

    # Default to 365 days (1 year) if neither is specified
    return 365
