"""Data models for ReactorCA."""

import datetime
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID


@dataclass
class SubjectIdentity:
    """Container for certificate subject identity information."""

    common_name: str
    organization: str = ""
    organization_unit: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""
    email: str = ""

    def to_x509_name(self: "SubjectIdentity") -> x509.Name:
        """Convert subject identity to x509.Name object."""
        subject_attributes = []

        # Common Name is required
        subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, self.common_name))

        # Add other attributes if provided
        if self.organization:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))
        if self.organization_unit:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organization_unit))
        if self.country:
            subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.country))
        if self.state:
            subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state))
        if self.locality:
            subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality))
        if self.email:
            subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email))

        return x509.Name(subject_attributes)

    @classmethod
    def from_x509_name(cls: type["SubjectIdentity"], name: x509.Name) -> "SubjectIdentity":
        """Create a SubjectIdentity from an x509.Name object."""

        # Helper function to safely extract attributes from the name
        def get_attr_value(oid: x509.ObjectIdentifier) -> str:
            attrs = name.get_attributes_for_oid(oid)
            return str(attrs[0].value) if attrs else ""

        return cls(
            common_name=get_attr_value(NameOID.COMMON_NAME),
            organization=get_attr_value(NameOID.ORGANIZATION_NAME),
            organization_unit=get_attr_value(NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=get_attr_value(NameOID.COUNTRY_NAME),
            state=get_attr_value(NameOID.STATE_OR_PROVINCE_NAME),
            locality=get_attr_value(NameOID.LOCALITY_NAME),
            email=get_attr_value(NameOID.EMAIL_ADDRESS),
        )


@dataclass
class AlternativeNames:
    """Container for Subject Alternative Names."""

    dns: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    email: list[str] = field(default_factory=list)
    uri: list[str] = field(default_factory=list)
    directory_name: list[str] = field(default_factory=list)
    registered_id: list[str] = field(default_factory=list)
    other_name: list[str] = field(default_factory=list)

    def is_empty(self: "AlternativeNames") -> bool:
        """Check if there are any SANs defined."""
        return not any(getattr(self, attr_name) for attr_name in self.__annotations__)


@dataclass
class ValidityConfig:
    """Configuration for certificate validity period."""

    days: int | None = None
    years: int | None = None

    def to_days(self: "ValidityConfig") -> int:
        """Convert validity configuration to days."""
        if self.days is not None:
            return self.days
        elif self.years is not None:
            return self.years * 365
        else:
            # Default to 1 year if neither is specified
            return 365


@dataclass
class ExportConfig:
    """Configuration for certificate export."""

    cert: str | None = None
    chain: str | None = None


@dataclass
class DeploymentConfig:
    """Configuration for certificate deployment."""

    command: str


@dataclass
class PasswordConfig:
    """Configuration for CA password handling."""

    min_length: int
    file: str = ""
    env_var: str = "REACTOR_CA_PASSWORD"


@dataclass
class HostConfig:
    """Configuration for a host certificate."""

    name: str
    common_name: str
    organization: str | None = None
    organization_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None
    alternative_names: AlternativeNames | None = None
    export: ExportConfig | None = None
    deploy: DeploymentConfig | None = None
    validity: ValidityConfig = field(default_factory=ValidityConfig)
    key_algorithm: str = "RSA2048"
    hash_algorithm: str | None = None


@dataclass
class CAConfig:
    """Configuration for the Certificate Authority."""

    common_name: str
    organization: str
    organization_unit: str
    country: str
    state: str
    locality: str
    email: str
    key_algorithm: str
    validity: ValidityConfig
    password: PasswordConfig
    hash_algorithm: str = "SHA256"


@dataclass
class CertificateMetadata:
    """Metadata for a certificate."""

    serial: str
    not_before: str
    not_after: str
    fingerprint: str
    days_remaining: int | None = None

    @classmethod
    def from_certificate(cls: type["CertificateMetadata"], cert: x509.Certificate) -> "CertificateMetadata":
        """Create CertificateMetadata from an X.509 certificate."""
        now = datetime.datetime.now(datetime.UTC)
        expiry_date = cert.not_valid_after.replace(tzinfo=datetime.UTC)
        days_remaining = (expiry_date - now).days

        return cls(
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before.isoformat(),
            not_after=cert.not_valid_after.isoformat(),
            fingerprint="SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
            days_remaining=days_remaining,
        )


@dataclass
class CertificateParams:
    """Parameters for certificate creation."""

    private_key: PrivateKeyTypes
    hostname: str
    ca_key: PrivateKeyTypes
    ca_cert: x509.Certificate
    validity_days: int = 365
    alt_names: AlternativeNames | None = None
    hash_algorithm: str | None = None
    host_config: HostConfig | None = None


@dataclass
class InventoryEntry:
    """Entry in the certificate inventory."""

    name: str
    serial: str
    not_after: str
    fingerprint: str
    renewal_count: int = 0
    rekeyed: bool = False
    days_remaining: int | None = None


@dataclass
class CAInventoryEntry:
    """CA entry in the certificate inventory."""

    serial: str
    not_after: str
    fingerprint: str
    days_remaining: int | None = None


@dataclass
class CSRInfo:
    """Information extracted from a Certificate Signing Request."""

    hostname: str
    subject: x509.Name
    alternative_names: AlternativeNames
    public_key: Any

    @classmethod
    def from_csr(cls: type["CSRInfo"], csr: x509.CertificateSigningRequest) -> "CSRInfo":
        """Create CSRInfo from a Certificate Signing Request."""
        # Extract hostname from subject common name
        hostname = None
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                hostname = attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
                break

        if not hostname:
            raise ValueError("Could not extract hostname from CSR")

        # Extract Subject Alternative Names
        alt_names = AlternativeNames()
        for ext in csr.extensions:
            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for san in ext.value:
                    if isinstance(san, x509.DNSName):
                        alt_names.dns.append(san.value)
                    elif isinstance(san, x509.IPAddress):
                        alt_names.ip.append(str(san.value))
                    elif isinstance(san, x509.RFC822Name):
                        alt_names.email.append(san.value)
                    elif isinstance(san, x509.UniformResourceIdentifier):
                        alt_names.uri.append(san.value)
                    # Additional SAN types could be added here

        return cls(
            hostname=hostname,
            subject=csr.subject,
            alternative_names=alt_names,
            public_key=csr.public_key(),
        )
