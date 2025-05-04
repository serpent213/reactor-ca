"""Data models and transformations for ReactorCA."""

import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import GeneralName, ObjectIdentifier
from cryptography.x509.general_name import (
    DirectoryName,
    OtherName,
    RegisteredID,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID

# Config


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

    @classmethod
    def process_dns_names(cls: type["AlternativeNames"], names: list[str]) -> list[x509.DNSName]:
        """Process DNS names into appropriate SAN format.

        Args:
        ----
            names: List of DNS name strings

        Returns:
        -------
            List of x509.DNSName objects

        """
        return [x509.DNSName(name) for name in names]

    @classmethod
    def process_ip_addresses(cls: type["AlternativeNames"], ips: list[str]) -> list[x509.IPAddress]:
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
            except ValueError as err:
                raise ValueError(f"Invalid IP address: {ip}") from err

        return result

    @classmethod
    def process_email_addresses(cls: type["AlternativeNames"], emails: list[str]) -> list[x509.RFC822Name]:
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
                raise ValueError(f"Invalid email address: {email}")

        return result

    @classmethod
    def process_uri_addresses(cls: type["AlternativeNames"], uris: list[str]) -> list[x509.UniformResourceIdentifier]:
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
                    raise ValueError(f"Invalid URI format: {uri}")
            except Exception as err:
                raise ValueError(f"Invalid URI: {uri}. Error: {str(err)}") from err

        return result

    @classmethod
    def process_directory_names(cls: type["AlternativeNames"], dns: list[str]) -> list[x509.DirectoryName]:
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
                    raise ValueError(f"No valid attributes found in directory name: {dn}")
            except Exception as err:
                raise ValueError(f"Invalid directory name: {dn}. Error: {str(err)}") from err

        return result

    @classmethod
    def process_registered_ids(cls: type["AlternativeNames"], oids: list[str]) -> list[x509.RegisteredID]:
        """Process OID strings into appropriate SAN format.

        Args:
        ----
            oids: List of OID strings

        Returns:
        -------
            List of valid x509.RegisteredID objects

        """
        result = []

        for oid in oids:
            try:
                # Validate OID format
                if re.match(r"^\d+(\.\d+)*$", oid):
                    result.append(RegisteredID(ObjectIdentifier(oid)))
                else:
                    raise ValueError(f"Invalid OID format: {oid}")
            except Exception as err:
                raise ValueError(f"Invalid OID: {oid}. Error: {str(err)}") from err

        return result

    @classmethod
    def process_other_names(cls: type["AlternativeNames"], other_names: list[str]) -> list[x509.OtherName]:
        """Process other name strings into appropriate SAN format.

        Args:
        ----
            other_names: List of other name strings (format "oid:value")

        Returns:
        -------
            List of valid x509.OtherName objects

        """
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
                    raise ValueError(f"Invalid format for other name: {other_name}, expected 'oid:value'")
            except Exception as err:
                raise ValueError(f"Invalid other name: {other_name}. Error: {str(err)}") from err

        return result

    def process_all_sans(self: "AlternativeNames") -> list[GeneralName]:
        """Process all Subject Alternative Name types from this instance.

        Returns
        -------
            List of all valid SAN objects

        """
        # Initialize the result list
        result: list[GeneralName] = []

        # Add DNS names
        if self.dns:
            result.extend(cast(list[GeneralName], self.process_dns_names(self.dns)))

        # Add IP addresses
        if self.ip:
            result.extend(cast(list[GeneralName], self.process_ip_addresses(self.ip)))

        # Add email addresses
        if self.email:
            result.extend(cast(list[GeneralName], self.process_email_addresses(self.email)))

        # Add URIs
        if self.uri:
            result.extend(cast(list[GeneralName], self.process_uri_addresses(self.uri)))

        # Add directory names
        if self.directory_name:
            result.extend(cast(list[GeneralName], self.process_directory_names(self.directory_name)))

        # Add registered IDs (OIDs)
        if self.registered_id:
            result.extend(cast(list[GeneralName], self.process_registered_ids(self.registered_id)))

        # Add other names
        if self.other_name:
            result.extend(cast(list[GeneralName], self.process_other_names(self.other_name)))

        return result


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
class CAConfig:
    """Configuration for the Certificate Authority."""

    common_name: str
    organization: str
    organization_unit: str
    country: str
    state: str
    locality: str
    email: str
    validity: ValidityConfig
    password: PasswordConfig
    key_algorithm: str
    hash_algorithm: str


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
    validity: ValidityConfig = field(default_factory=ValidityConfig)
    export: ExportConfig | None = None
    deploy: DeploymentConfig | None = None
    key_algorithm: str | None = None
    hash_algorithm: str | None = None


# Core Runtime Entities


@dataclass
class Config:
    """Represents the runtime configuration."""

    config_path: str
    store_path: str


@dataclass
class CA:
    """Represents the runtime Certificate Authority."""

    config: Config
    ca_config: CAConfig
    cert: x509.Certificate
    key: PrivateKeyTypes


@dataclass
class Host:
    """Represents a runtime host."""

    host_config: HostConfig
    cert: x509.Certificate
    key: PrivateKeyTypes


# Store


@dataclass
class InventoryEntry:
    """Entry in the certificate inventory."""

    short_name: str
    serial: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    fingerprint_sha256: str
    renewal_count: int = 0
    rekey_count: int = 0

    @classmethod
    def from_certificate(cls: type["InventoryEntry"], short_name: str, cert: x509.Certificate) -> "InventoryEntry":
        """Create InventoryEntry from an X.509 certificate."""
        return cls(
            short_name=short_name,
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            fingerprint_sha256="SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
        )


@dataclass
class CAInventoryEntry:
    """CA entry in the certificate inventory."""

    serial: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    fingerprint_sha256: str
    renewal_count: int = 0
    rekey_count: int = 0

    @classmethod
    def from_certificate(cls: type["CAInventoryEntry"], cert: x509.Certificate) -> "CAInventoryEntry":
        """Create CAInventoryEntry from an X.509 CA certificate."""
        return cls(
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            fingerprint_sha256="SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
        )


# Certificates


@dataclass
class SubjectIdentity:
    """Container for certificate subject identity (X.509 name) information."""

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

    @classmethod
    def from_certificate(cls: type["SubjectIdentity"], cert: x509.Certificate) -> "SubjectIdentity":
        """Create a SubjectIdentity from an X.509 certificate."""
        return cls.from_x509_name(cert.subject)

    @classmethod
    def create_from_config(
        cls: type["SubjectIdentity"], hostname: str, ca_config: CAConfig, host_config: HostConfig | None = None
    ) -> "SubjectIdentity":
        """Create a SubjectIdentity from CA config and optional host config.

        Args:
        ----
            hostname: The hostname to use as common name
            ca_config: The CA configuration containing default values
            host_config: Optional host configuration that can override CA defaults

        Returns:
        -------
            SubjectIdentity with fields from host_config or CA config

        """
        return cls(
            common_name=hostname,
            organization=host_config.organization
            if host_config and host_config.organization
            else ca_config.organization,
            organization_unit=host_config.organization_unit
            if host_config and host_config.organization_unit
            else ca_config.organization_unit,
            country=host_config.country if host_config and host_config.country else ca_config.country,
            state=host_config.state if host_config and host_config.state else ca_config.state,
            locality=host_config.locality if host_config and host_config.locality else ca_config.locality,
            email=host_config.email if host_config and host_config.email else ca_config.email,
        )


@dataclass
class CACertificateParams:
    """Parameters for CA certificate creation."""

    subject_identity: SubjectIdentity
    private_key: PrivateKeyTypes | None = None
    validity_days: int | None = None
    alt_names: AlternativeNames | None = None
    hash_algorithm: str | None = None

    @classmethod
    def from_ca_config(
        cls: type["CACertificateParams"], ca_config: CAConfig, private_key: PrivateKeyTypes | None = None
    ) -> "CACertificateParams":
        """Create CACertificateParams from a CA configuration.

        Args:
        ----
            ca_config: CA configuration with subject details and validity
            private_key: Optional private key to use. If None, one will be generated.

        Returns:
        -------
            A CACertificateParams object with values from CA config

        """
        # Create subject identity from CA config
        subject_identity = SubjectIdentity(
            common_name=ca_config.common_name,
            organization=ca_config.organization,
            organization_unit=ca_config.organization_unit,
            country=ca_config.country,
            state=ca_config.state,
            locality=ca_config.locality,
            email=ca_config.email,
        )

        # Calculate validity days from config
        validity_days = ca_config.validity.to_days() if ca_config.validity else None

        return cls(
            subject_identity=subject_identity,
            private_key=private_key,
            validity_days=validity_days,
            hash_algorithm=ca_config.hash_algorithm,
        )


@dataclass
class CertificateParams:
    """Parameters for certificate creation."""

    subject_identity: SubjectIdentity
    ca: CA
    private_key: PrivateKeyTypes | None = None
    validity_days: int | None = None
    alt_names: AlternativeNames | None = None
    hash_algorithm: str | None = None

    @classmethod
    def from_host_config(
        cls: type["CertificateParams"], host_config: HostConfig, ca: CA, private_key: PrivateKeyTypes | None = None
    ) -> "CertificateParams":
        """Create CertificateParams from a host configuration.

        Args:
        ----
            host_config: Host configuration with details for certificate
            ca: CA object containing certificate, key, and configuration
            private_key: Optional private key to use. If None, one will be generated.

        Returns:
        -------
            A CertificateParams object with values from host config

        """
        # Create subject identity from CA config and host config
        subject_identity = SubjectIdentity.create_from_config(
            hostname=host_config.common_name, ca_config=ca.ca_config, host_config=host_config
        )

        # Calculate validity days from config
        validity_days = host_config.validity.to_days() if host_config.validity else None

        return cls(
            subject_identity=subject_identity,
            ca=ca,
            private_key=private_key,
            validity_days=validity_days,
            alt_names=host_config.alternative_names,
            hash_algorithm=host_config.hash_algorithm,
        )


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
