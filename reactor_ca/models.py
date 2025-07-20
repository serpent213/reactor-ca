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

    @field_validator("dns", "ip", "email", "uri", "directory_name", "registered_id", "other_name")
    @classmethod
    def validate_san_fields(cls: type["AlternativeNames"], v: list[str], info: Field.ValidationInfo) -> list[str]:
        """Validate all SAN fields using a single dispatch method."""
        validators = {
            "dns": cls._validate_dns_name,
            "ip": cls._validate_ip_address,
            "email": cls._validate_email_address,
            "uri": cls._validate_uri,
            "directory_name": cls._validate_directory_name,
            "registered_id": cls._validate_oid,
            "other_name": cls._validate_other_name,
        }
        validator = validators.get(info.field_name)
        if validator:
            for item in v:
                validator(item)
        return v

    @staticmethod
    def _validate_dns_name(name: str) -> None:
        if not re.match(r"^(?

---
Tokens: 57861 input, 35775 output, 101458 total
Cost: $0.072326 input + $0.357750 output = $0.430076 total
