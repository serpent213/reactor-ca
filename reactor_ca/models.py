"""Data models and transformations for ReactorCA."""

import ipaddress
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import GeneralName, ObjectIdentifier
from cryptography.x509.general_name import DirectoryName, OtherName, RegisteredID, UniformResourceIdentifier
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, Field, field_validator, model_validator

from reactor_ca.defaults import (
    DEFAULT_CA_HASH_ALGORITHM,
    DEFAULT_CA_KEY_ALGORITHM,
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_HOST_HASH_ALGORITHM,
    DEFAULT_HOST_KEY_ALGORITHM,
    DEFAULT_HOST_VALIDITY_DAYS,
    DEFAULT_PASSWORD_MIN_LENGTH,
)
from reactor_ca.result import Failure, Result, Success
from reactor_ca.types import HashAlgorithm, KeyAlgorithm

# Config


class AlternativeNames(BaseModel):
    """Container for Subject Alternative Names."""

    dns: list[str] = Field(default_factory=list)
    ip: list[str] = Field(default_factory=list)
    email: list[str] = Field(default_factory=list)
    uri: list[str] = Field(default_factory=list)
    directory_name: list[str] = Field(default_factory=list)
    registered_id: list[str] = Field(default_factory=list)
    other_name: list[str] = Field(default_factory=list)

    @field_validator("dns")
    @classmethod
    def validate_dns(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate DNS names have proper format."""
        if not v:
            return v

        for name in v:
            if not re.match(
                r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$",
                name,
            ):
                raise ValueError(f"Invalid DNS name format: {name}")
        return v

    @field_validator("ip")
    @classmethod
    def validate_ip(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate IP addresses are valid."""
        if not v:
            return v

        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError as err:
                raise ValueError(f"Invalid IP address: {ip}") from err
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate email addresses have proper format."""
        if not v:
            return v

        for email in v:
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                raise ValueError(f"Invalid email address: {email}")
        return v

    @field_validator("uri")
    @classmethod
    def validate_uri(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate URIs have proper format."""
        if not v:
            return v

        for uri in v:
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\.-]*://.*$", uri):
                raise ValueError(f"Invalid URI format: {uri}")
        return v

    @field_validator("directory_name")
    @classmethod
    def validate_directory_name(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate directory names have proper format."""
        if not v:
            return v

        for dn in v:
            if not re.match(r"^(CN|O|OU|C|ST|L|E)=.*?(,(CN|O|OU|C|ST|L|E)=.*?)*$", dn):
                raise ValueError(f"Invalid directory name format: {dn}")
        return v

    @field_validator("registered_id")
    @classmethod
    def validate_registered_id(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate registered IDs have proper format."""
        if not v:
            return v

        for oid in v:
            if not re.match(r"^\d+(\.\d+)*$", oid):
                raise ValueError(f"Invalid OID format: {oid}")
        return v

    @field_validator("other_name")
    @classmethod
    def validate_other_name(cls: type["AlternativeNames"], v: list[str] | None) -> list[str] | None:
        """Validate other names have proper format."""
        if not v:
            return v

        for other in v:
            if not re.match(r"^\d+(\.\d+)*:.*$", other):
                raise ValueError(f"Invalid other name format: {other}")
        return v

    def is_empty(self: "AlternativeNames") -> bool:
        """Check if there are any SANs defined."""
        return not any(
            [self.dns, self.ip, self.email, self.uri, self.directory_name, self.registered_id, self.other_name]
        )

    def to_dns_names(self: "AlternativeNames") -> Result[list[x509.DNSName], str]:
        """Convert DNS names to appropriate SAN format."""
        try:
            return Success([x509.DNSName(name) for name in self.dns])
        except Exception as err:
            return Failure(f"Error converting DNS names: {str(err)}")

    def to_ip_addresses(self: "AlternativeNames") -> Result[list[x509.IPAddress], str]:
        """Convert IP addresses to appropriate SAN format."""
        result = []

        try:
            for ip in self.ip:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    result.append(x509.IPAddress(ip_obj))
                except ValueError:
                    return Failure(f"Invalid IP address: {ip}")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting IP addresses: {str(err)}")

    def to_email_addresses(self: "AlternativeNames") -> Result[list[x509.RFC822Name], str]:
        """Convert email addresses to appropriate SAN format."""
        result = []

        try:
            for email in self.email:
                # Simple email validation
                if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    result.append(x509.RFC822Name(email))
                else:
                    return Failure(f"Invalid email address: {email}")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting email addresses: {str(err)}")

    def to_uri_addresses(self: "AlternativeNames") -> Result[list[x509.UniformResourceIdentifier], str]:
        """Convert URIs to appropriate SAN format."""
        result = []

        try:
            for uri in self.uri:
                # Validate URI
                parsed = urlparse(uri)
                if parsed.scheme and parsed.netloc:
                    result.append(UniformResourceIdentifier(uri))
                else:
                    return Failure(f"Invalid URI format: {uri}")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting URIs: {str(err)}")

    def to_directory_names(self: "AlternativeNames") -> Result[list[x509.DirectoryName], str]:
        """Convert directory names to appropriate SAN format."""
        result = []

        try:
            for dn in self.directory_name:
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
                    return Failure(f"No valid attributes found in directory name: {dn}")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting directory names: {str(err)}")

    def to_registered_ids(self: "AlternativeNames") -> Result[list[x509.RegisteredID], str]:
        """Convert OID strings to appropriate SAN format."""
        result = []

        try:
            for oid in self.registered_id:
                # Validate OID format
                if re.match(r"^\d+(\.\d+)*$", oid):
                    result.append(RegisteredID(ObjectIdentifier(oid)))
                else:
                    return Failure(f"Invalid OID format: {oid}")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting OIDs: {str(err)}")

    def to_other_names(self: "AlternativeNames") -> Result[list[x509.OtherName], str]:
        """Convert other name strings to appropriate SAN format."""
        result = []

        try:
            for other_name in self.other_name:
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
                        return Failure("Invalid OID format")
                else:
                    return Failure(f"Invalid format for other name: {other_name}, expected 'oid:value'")

            return Success(result)
        except Exception as err:
            return Failure(f"Error converting other names: {str(err)}")

    def to_general_names(self: "AlternativeNames") -> Result[list[GeneralName], str]:
        """Convert all Subject Alternative Name types to a list of GeneralName objects."""
        result: list[GeneralName] = []

        # Add DNS names
        if self.dns:
            dns_result = self.to_dns_names()
            if isinstance(dns_result, Failure):
                return dns_result
            result.extend(cast(list[GeneralName], dns_result.unwrap()))

        # Add IP addresses
        if self.ip:
            ip_result = self.to_ip_addresses()
            if isinstance(ip_result, Failure):
                return ip_result
            result.extend(cast(list[GeneralName], ip_result.unwrap()))

        # Add email addresses
        if self.email:
            email_result = self.to_email_addresses()
            if isinstance(email_result, Failure):
                return email_result
            result.extend(cast(list[GeneralName], email_result.unwrap()))

        # Add URIs
        if self.uri:
            uri_result = self.to_uri_addresses()
            if isinstance(uri_result, Failure):
                return uri_result
            result.extend(cast(list[GeneralName], uri_result.unwrap()))

        # Add directory names
        if self.directory_name:
            dn_result = self.to_directory_names()
            if isinstance(dn_result, Failure):
                return dn_result
            result.extend(cast(list[GeneralName], dn_result.unwrap()))

        # Add registered IDs (OIDs)
        if self.registered_id:
            oid_result = self.to_registered_ids()
            if isinstance(oid_result, Failure):
                return oid_result
            result.extend(cast(list[GeneralName], oid_result.unwrap()))

        # Add other names
        if self.other_name:
            other_result = self.to_other_names()
            if isinstance(other_result, Failure):
                return other_result
            result.extend(cast(list[GeneralName], other_result.unwrap()))

        return Success(result)


class ValidityConfig(BaseModel):
    """Configuration for certificate validity period."""

    days: int | None = Field(None, gt=0, description="Validity period in days")
    years: int | None = Field(None, gt=0, description="Validity period in years")

    @model_validator(mode="after")
    def validate_validity_period(self: "ValidityConfig") -> "ValidityConfig":
        """Ensure exactly one of days or years is specified."""
        if (self.days is None and self.years is None) or (self.days is not None and self.years is not None):
            raise ValueError("Exactly one of 'days' or 'years' must be specified")
        return self

    def to_days(self: "ValidityConfig") -> Result[int, str]:
        """Convert validity configuration to days."""
        if self.days is not None:
            return Success(self.days)
        if self.years is not None:
            return Success(self.years * 365)
        # This should never happen due to the validator, but keeping for robustness
        return Failure("No validity specified")


class ExportConfig(BaseModel):
    """Configuration for certificate export."""

    cert: str | None = None
    chain: str | None = None


class DeploymentConfig(BaseModel):
    """Configuration for certificate deployment."""

    command: str


class PasswordConfig(BaseModel):
    """Configuration for CA password handling."""

    min_length: int = Field(..., ge=8)
    file: str | None = None
    env_var: str | None = None


class CAConfig(BaseModel):
    """Configuration for the Certificate Authority."""

    common_name: str
    organization: str | None = None
    organization_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None
    # mypy incorrectly thinks we need to specify both days and years
    validity: ValidityConfig = Field(default_factory=lambda: ValidityConfig(days=DEFAULT_CA_VALIDITY_DAYS))  # type: ignore
    password: PasswordConfig = Field(default_factory=lambda: PasswordConfig(min_length=DEFAULT_PASSWORD_MIN_LENGTH))
    key_algorithm: KeyAlgorithm = DEFAULT_CA_KEY_ALGORITHM
    hash_algorithm: HashAlgorithm = DEFAULT_CA_HASH_ALGORITHM


class HostConfig(BaseModel):
    """Configuration for a host certificate."""

    host_id: str
    common_name: str
    organization: str | None = None
    organization_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None
    alternative_names: AlternativeNames | None = None
    # mypy incorrectly thinks we need to specify both days and years
    validity: ValidityConfig = Field(default_factory=lambda: ValidityConfig(days=DEFAULT_HOST_VALIDITY_DAYS))  # type: ignore
    key_algorithm: KeyAlgorithm = DEFAULT_HOST_KEY_ALGORITHM
    hash_algorithm: HashAlgorithm = DEFAULT_HOST_HASH_ALGORITHM
    export: ExportConfig | None = None
    deploy: DeploymentConfig | None = None


# Core Runtime Entities


class Config(BaseModel):
    """Represents the runtime configuration."""

    config_path: Path
    ca_config: CAConfig | None = None
    hosts_config: dict[str, HostConfig] | None = None


class CA(BaseModel):
    """Represents the runtime Certificate Authority."""

    model_config = {"arbitrary_types_allowed": True}

    ca_config: CAConfig
    cert: x509.Certificate
    key: PrivateKeyTypes


class Host(BaseModel):
    """Represents a runtime host."""

    model_config = {"arbitrary_types_allowed": True}

    host_config: HostConfig
    cert: x509.Certificate
    key: PrivateKeyTypes


# Store


class CAInventoryEntry(BaseModel):
    """CA entry in the certificate inventory."""

    renewal_count: int = 0
    rekey_count: int = 0


class InventoryEntry(BaseModel):
    """Entry in the certificate inventory."""

    host_id: str
    renewal_count: int = 0
    rekey_count: int = 0


class Inventory(BaseModel):
    """Top-level certificate inventory."""

    ca: CAInventoryEntry
    hosts: list[InventoryEntry]


class Store(BaseModel):
    """Top-level store entity."""

    path: Path
    password: str | None = None
    unlocked: bool = False


# Certificates


class SubjectIdentity(BaseModel):
    """Container for certificate subject identity (X.509 name) information."""

    common_name: str
    organization: str | None = None
    organization_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None

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
    def from_x509_name(cls: type["SubjectIdentity"], name: x509.Name) -> Result["SubjectIdentity", str]:
        """Create a SubjectIdentity from an x509.Name object."""
        try:
            # Helper function to safely extract attributes from the name
            def get_attr_value(oid: x509.ObjectIdentifier) -> str:
                attrs = name.get_attributes_for_oid(oid)
                return str(attrs[0].value) if attrs else ""

            # Common name is required
            common_name = get_attr_value(NameOID.COMMON_NAME)
            if not common_name:
                return Failure("X.509 name missing required Common Name")

            return Success(
                cls(
                    common_name=common_name,
                    organization=get_attr_value(NameOID.ORGANIZATION_NAME),
                    organization_unit=get_attr_value(NameOID.ORGANIZATIONAL_UNIT_NAME),
                    country=get_attr_value(NameOID.COUNTRY_NAME),
                    state=get_attr_value(NameOID.STATE_OR_PROVINCE_NAME),
                    locality=get_attr_value(NameOID.LOCALITY_NAME),
                    email=get_attr_value(NameOID.EMAIL_ADDRESS),
                )
            )
        except Exception as err:
            return Failure(f"Error extracting subject identity: {str(err)}")

    @classmethod
    def from_certificate(cls: type["SubjectIdentity"], cert: x509.Certificate) -> Result["SubjectIdentity", str]:
        """Create a SubjectIdentity from an X.509 certificate."""
        return cls.from_x509_name(cert.subject)

    @classmethod
    def from_config(
        cls: type["SubjectIdentity"],
        ca_config: CAConfig,
        host_config: HostConfig | None = None,
    ) -> Result["SubjectIdentity", str]:
        """Create a SubjectIdentity from CA config with fields optionally overridden by a host config.

        Args:
        ----
            ca_config: The CA configuration containing default values
            host_config: Optional host configuration that can override CA defaults

        Returns:
        -------
            Result containing SubjectIdentity with fields from host config or CA config or an error

        """
        try:
            return Success(
                cls(
                    common_name=host_config.common_name if host_config else ca_config.common_name,
                    organization=(host_config and host_config.organization) or ca_config.organization or None,
                    organization_unit=(host_config and host_config.organization_unit)
                    or ca_config.organization_unit
                    or None,
                    country=(host_config and host_config.country) or ca_config.country or None,
                    state=(host_config and host_config.state) or ca_config.state or None,
                    locality=(host_config and host_config.locality) or ca_config.locality or None,
                    email=(host_config and host_config.email) or ca_config.email or None,
                )
            )
        except Exception as err:
            return Failure(f"Error creating subject identity from config: {str(err)}")


class CACertificateParams(BaseModel):
    """Parameters for CA certificate creation."""

    model_config = {"arbitrary_types_allowed": True}

    subject_identity: SubjectIdentity
    private_key: PrivateKeyTypes | None = None
    validity_days: int | None = None
    alt_names: AlternativeNames | None = None
    hash_algorithm: HashAlgorithm | None = None

    @classmethod
    def from_ca_config(
        cls: type["CACertificateParams"],
        ca_config: CAConfig,
        private_key: PrivateKeyTypes,
    ) -> Result["CACertificateParams", str]:
        """Create CACertificateParams from a CA configuration.

        Args:
        ----
            ca_config: CA configuration with subject details and validity
            private_key: Private key to use

        Returns:
        -------
            Result containing CACertificateParams object with values from CA config or an error

        """
        try:
            subject_identity_result = SubjectIdentity.from_config(ca_config=ca_config)
            if isinstance(subject_identity_result, Failure):
                return subject_identity_result
            subject_identity = subject_identity_result.unwrap()

            validity_days_result = ca_config.validity.to_days()
            if isinstance(validity_days_result, Failure):
                return validity_days_result
            validity_days = validity_days_result.unwrap()

            return Success(
                cls(
                    subject_identity=subject_identity,
                    private_key=private_key,
                    validity_days=validity_days,
                    hash_algorithm=ca_config.hash_algorithm,
                )
            )
        except Exception as err:
            return Failure(f"Error creating CA certificate parameters: {str(err)}")


class CertificateParams(BaseModel):
    """Parameters for certificate creation."""

    model_config = {"arbitrary_types_allowed": True}

    subject_identity: SubjectIdentity
    ca: CA
    private_key: PrivateKeyTypes | None = None
    validity_days: int | None = None
    alt_names: AlternativeNames | None = None
    hash_algorithm: HashAlgorithm | None = None

    @classmethod
    def from_host_config(
        cls: type["CertificateParams"],
        host_config: HostConfig,
        ca: CA,
        private_key: PrivateKeyTypes | None = None,
    ) -> Result["CertificateParams", str]:
        """Create CertificateParams from a host configuration.

        Args:
        ----
            host_config: Host configuration with details for certificate
            ca: CA object containing certificate, key, and configuration
            private_key: Optional private key to use. If None, one will be generated.

        Returns:
        -------
            Result containing CertificateParams object with values from host config or an error

        """
        try:
            subject_identity_result = SubjectIdentity.from_config(ca_config=ca.ca_config, host_config=host_config)
            if isinstance(subject_identity_result, Failure):
                return subject_identity_result
            subject_identity = subject_identity_result.unwrap()

            validity_days_result = host_config.validity.to_days()
            if isinstance(validity_days_result, Failure):
                return validity_days_result
            validity_days = validity_days_result.unwrap()

            return Success(
                cls(
                    subject_identity=subject_identity,
                    ca=ca,
                    private_key=private_key,
                    validity_days=validity_days,
                    alt_names=host_config.alternative_names,
                    hash_algorithm=host_config.hash_algorithm,
                )
            )
        except Exception as err:
            return Failure(f"Error creating certificate parameters from host config: {str(err)}")


class CSRInfo(BaseModel):
    """Information extracted from a Certificate Signing Request."""

    model_config = {"arbitrary_types_allowed": True}

    hostname: str
    subject: x509.Name
    alternative_names: AlternativeNames
    public_key: Any

    @classmethod
    def from_csr(cls: type["CSRInfo"], csr: x509.CertificateSigningRequest) -> Result["CSRInfo", str]:
        """Create CSRInfo from a Certificate Signing Request."""
        try:
            # Extract hostname from subject common name
            hostname = None
            for attr in csr.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    hostname = attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
                    break

            if not hostname:
                return Failure("Could not extract hostname from CSR (missing Common Name)")

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

            return Success(
                cls(
                    hostname=hostname,
                    subject=csr.subject,
                    alternative_names=alt_names,
                    public_key=csr.public_key(),
                )
            )
        except Exception as err:
            return Failure(f"Error parsing CSR: {str(err)}")
