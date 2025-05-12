"""Type definitions for ReactorCA."""

from enum import StrEnum


class KeyAlgorithm(StrEnum):
    """Supported key algorithms."""
    
    RSA2048 = "RSA2048"
    RSA3072 = "RSA3072"
    RSA4096 = "RSA4096"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    ECP521 = "ECP521"
    ED25519 = "ED25519"
    ED448 = "ED448"


class HashAlgorithm(StrEnum):
    """Supported hash algorithms."""
    
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"