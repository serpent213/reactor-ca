"""Certificate Authority operations for ReactorCA.

This module provides high-level functions for managing the Certificate Authority
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
import json
from pathlib import Path
from typing import Any, Optional, Dict, Tuple, TYPE_CHECKING

from cryptography import x509

if TYPE_CHECKING:
    from reactor_ca import models
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from reactor_ca.config import load_ca_config, validate_config
from reactor_ca.inventory import read_inventory, update_inventory_with_ca_cert
from reactor_ca.models import CAConfig, Store, SubjectIdentity
from reactor_ca.password import get_password, verify_password
from reactor_ca.result import Result, Success, Failure
from reactor_ca.store import ca_exists, read_ca_cert, read_ca_key, write_ca_cert, write_ca_key
from reactor_ca.x509_crypto import (
    generate_key,
    get_hash_algorithm,
    create_ca_certificate,
    verify_key_algorithm,
    deserialize_certificate,
    deserialize_private_key,
    create_ca_inventory_entry,
)

# Constants for expiration warnings
EXPIRY_CRITICAL = 30  # days
EXPIRY_WARNING = 90  # days


def issue_ca(config: 'models.Config', store: 'models.Store') -> Result[Dict[str, Any], str]:
    """Issue a CA certificate. Creates one if it doesn't exist, renews if it does.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with CA info dict or error message

    """
    # Check if CA already exists
    is_new_ca = not ca_exists(store.path)

    # Get CA config directly from the Config object
    ca_config = config.ca_config

    # Get expected key algorithm from config
    key_algorithm = ca_config.key_algorithm

    if is_new_ca:
        # Creating a new CA
        # Make sure we have a password
        if not store.password or not store.unlocked:
            return Failure("Store must be unlocked and have a password set")
            
        password = store.password

        # Generate key
        key_result = generate_key(key_algorithm)
        if not key_result:
            return Failure(f"Failed to generate key: {key_result.error}")
        private_key = key_result.unwrap()

        # Generate self-signed certificate
        validity_days = ca_config.validity.to_days()

        # Create CA certificate params
        subject_identity = SubjectIdentity(
            common_name=ca_config.common_name,
            organization=ca_config.organization,
            organization_unit=ca_config.organization_unit,
            country=ca_config.country,
            state=ca_config.state,
            locality=ca_config.locality,
            email=ca_config.email,
        )

        cert_result = create_ca_certificate(
            private_key=private_key,
            subject_identity=subject_identity,
            validity_days=validity_days,
            hash_algorithm=ca_config.hash_algorithm,
        )

        if not cert_result:
            return Failure(f"Failed to create CA certificate: {cert_result.error}")
        cert = cert_result.unwrap()

        # Save key and certificate
        key_bytes_result = private_key.private_bytes(
            encoding=x509.serialization.Encoding.PEM,
            format=x509.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=x509.serialization.NoEncryption(),
        )
        key_save_result = write_ca_key(store.path, key_bytes_result, password)
        if not key_save_result:
            return Failure(f"Failed to save CA key: {key_save_result.error}")

        cert_bytes = cert.public_bytes(x509.serialization.Encoding.PEM)
        cert_save_result = write_ca_cert(store.path, cert_bytes)
        if not cert_save_result:
            return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

        # Update inventory
        inventory_result = read_inventory(Path(store.path))
        if inventory_result:
            inventory = inventory_result.unwrap()
            update_result = update_inventory_with_ca_cert(Path(store.path), cert, inventory)
            if not update_result:
                return Failure(f"Failed to update inventory: {update_result.error}")

        return Success(
            {
                "action": "created",
                "cert_path": str(Path(store.path) / "ca" / "cert.pem"),
                "key_path": str(Path(store.path) / "ca" / "key.pem"),
                "common_name": ca_config.common_name,
                "validity_days": validity_days,
            }
        )
    else:
        # Renewing existing CA certificate
        # Make sure we have a password
        if not store.password or not store.unlocked:
            return Failure("Store must be unlocked and have a password set")
            
        password = store.password

        # Load the CA key
        ca_key_result = read_ca_key(store.path, password)
        if not ca_key_result:
            return Failure(f"Failed to load CA key: {ca_key_result.error}")

        key_data = ca_key_result.unwrap()
        private_key_result = deserialize_private_key(key_data, password.encode() if password else None)
        if not private_key_result:
            return Failure(f"Failed to deserialize private key: {private_key_result.error}")

        private_key = private_key_result.unwrap()

        # Verify that the existing key matches the algorithm in the config
        key_algorithm_result = verify_key_algorithm(private_key, key_algorithm)
        if not key_algorithm_result:
            return Failure(f"Key algorithm mismatch: {key_algorithm_result.error}")

        # Generate new certificate with existing key
        validity_days = ca_config.validity.to_days()

        # Create CA certificate params
        subject_identity = SubjectIdentity(
            common_name=ca_config.common_name,
            organization=ca_config.organization,
            organization_unit=ca_config.organization_unit,
            country=ca_config.country,
            state=ca_config.state,
            locality=ca_config.locality,
            email=ca_config.email,
        )

        cert_result = create_ca_certificate(
            private_key=private_key,
            subject_identity=subject_identity,
            validity_days=validity_days,
            hash_algorithm=ca_config.hash_algorithm,
        )

        if not cert_result:
            return Failure(f"Failed to create CA certificate: {cert_result.error}")
        cert = cert_result.unwrap()

        # Save the new certificate
        cert_bytes = cert.public_bytes(x509.serialization.Encoding.PEM)
        cert_save_result = write_ca_cert(store.path, cert_bytes)
        if not cert_save_result:
            return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

        # Update inventory
        inventory_result = read_inventory(Path(store.path))
        if inventory_result:
            inventory = inventory_result.unwrap()
            update_result = update_inventory_with_ca_cert(Path(store.path), cert, inventory)
            if not update_result:
                return Failure(f"Failed to update inventory: {update_result.error}")

        return Success(
            {
                "action": "renewed",
                "cert_path": str(Path(store.path) / "ca" / "cert.pem"),
                "common_name": ca_config.common_name,
                "validity_days": validity_days,
            }
        )


def rekey_ca(config: 'models.Config', store: 'models.Store') -> Result[Dict[str, Any], str]:
    """Generate a new key and renew the CA certificate.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with CA info dict or error message

    """
    # Check if CA exists
    if not ca_exists(store.path):
        return Failure("CA certificate or key not found. Please initialize the CA first.")
        
    # Make sure we have a password
    if not store.password or not store.unlocked:
        return Failure("Store must be unlocked and have a password set")
        
    password = store.password
        
    # Get CA config directly from the Config object
    ca_config = config.ca_config

    # Generate a new key
    key_algorithm = ca_config.key_algorithm
    key_result = generate_key(key_algorithm)
    if not key_result:
        return Failure(f"Failed to generate key: {key_result.error}")
    new_ca_key = key_result.unwrap()

    # Generate a new certificate with the new key
    validity_days = ca_config.validity.to_days()

    # Create CA certificate params
    subject_identity = SubjectIdentity(
        common_name=ca_config.common_name,
        organization=ca_config.organization,
        organization_unit=ca_config.organization_unit,
        country=ca_config.country,
        state=ca_config.state,
        locality=ca_config.locality,
        email=ca_config.email,
    )

    cert_result = create_ca_certificate(
        private_key=new_ca_key,
        subject_identity=subject_identity,
        validity_days=validity_days,
        hash_algorithm=ca_config.hash_algorithm,
    )

    if not cert_result:
        return Failure(f"Failed to create CA certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save the new certificate and key
    key_bytes_result = new_ca_key.private_bytes(
        encoding=x509.serialization.Encoding.PEM,
        format=x509.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=x509.serialization.NoEncryption(),
    )
    key_save_result = write_ca_key(store.path, key_bytes_result, password)
    if not key_save_result:
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_bytes = cert.public_bytes(x509.serialization.Encoding.PEM)
    cert_save_result = write_ca_cert(store.path, cert_bytes)
    if not cert_save_result:
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store.path))
    if inventory_result:
        inventory = inventory_result.unwrap()
        update_result = update_inventory_with_ca_cert(Path(store.path), cert, inventory)
        if not update_result:
            return Failure(f"Failed to update inventory: {update_result.error}")

    return Success(
        {
            "action": "rekeyed",
            "cert_path": str(Path(store.path) / "ca" / "cert.pem"),
            "key_path": str(Path(store.path) / "ca" / "key.pem"),
            "common_name": ca_config.common_name,
            "validity_days": validity_days,
        }
    )


def import_ca(
    cert_path: Path, key_path: Path, config: 'models.Config', store: 'models.Store', 
    src_password: Optional[str] = None
) -> Result[Dict[str, Any], str]:
    """Import an existing CA certificate and key.

    Args:
    ----
        cert_path: Path to the certificate file
        key_path: Path to the key file
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        src_password: Optional password for the source key

    Returns:
    -------
        Result with CA info dict or error message

    """
    # Check if CA exists in the store
    if ca_exists(store.path):
        return Failure("CA already exists in store. Please remove it first or use a different store.")

    # Check if source files exist
    if not cert_path.exists():
        return Failure(f"Certificate file not found: {cert_path}")

    if not key_path.exists():
        return Failure(f"Key file not found: {key_path}")
        
    # Make sure we have a password in the store for saving
    if not store.password or not store.unlocked:
        return Failure("Store must be unlocked and have a password set for saving imported CA")
        
    dest_password = store.password

    # Load the certificate
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert_result = deserialize_certificate(cert_data)
        if not cert_result:
            return Failure(f"Failed to load certificate: {cert_result.error}")
        cert = cert_result.unwrap()
    except Exception as e:
        return Failure(f"Error loading certificate: {str(e)}")

    # Load and validate the key
    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
    except Exception as e:
        return Failure(f"Error loading key file: {str(e)}")

    # Try to load it without password first
    try:
        private_key_result = deserialize_private_key(key_data, None)
        if not private_key_result:
            # Need a password for the source key
            if src_password:
                private_key_result = deserialize_private_key(key_data, src_password.encode())
                if not private_key_result:
                    return Failure(f"Failed to decrypt key with provided password: {private_key_result.error}")
            else:
                return Failure("Key is password-protected. Please provide a source key password.")
    except Exception as e:
        return Failure(f"Error loading key: {str(e)}")

    private_key = private_key_result.unwrap()

    # Verify that the certificate and key match
    public_key_cert = cert.public_key()
    public_key = private_key.public_key()

    if public_key_cert.public_bytes(
        x509.serialization.Encoding.PEM, x509.serialization.PublicFormat.SubjectPublicKeyInfo
    ) != public_key.public_bytes(
        x509.serialization.Encoding.PEM, x509.serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        return Failure("Certificate and key do not match")

    # Save certificate and key
    cert_bytes = cert.public_bytes(x509.serialization.Encoding.PEM)
    cert_save_result = write_ca_cert(store.path, cert_bytes)
    if not cert_save_result:
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    key_bytes = private_key.private_bytes(
        encoding=x509.serialization.Encoding.PEM,
        format=x509.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=x509.serialization.NoEncryption(),
    )
    key_save_result = write_ca_key(store.path, key_bytes, dest_password)
    if not key_save_result:
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store.path))
    if inventory_result:
        inventory = inventory_result.unwrap()
        update_result = update_inventory_with_ca_cert(Path(store.path), cert, inventory)
        if not update_result:
            return Failure(f"Failed to update inventory: {update_result.error}")

    # Extract metadata for return info
    subject = cert.subject
    common_name = ""
    for attr in subject:
        if attr.oid.dotted_string == "2.5.4.3":  # Common Name
            common_name = attr.value

    return Success(
        {
            "action": "imported",
            "cert_path": str(Path(store.path) / "ca" / "cert.pem"),
            "key_path": str(Path(store.path) / "ca" / "key.pem"),
            "common_name": common_name,
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_until": cert.not_valid_after.isoformat(),
        }
    )


def get_ca_info(store: 'models.Store') -> Result[Dict[str, Any], str]:
    """Get information about the CA certificate.

    Args:
    ----
        store: Store object containing path and password information

    Returns:
    -------
        Result with CA info dictionary or error message

    """
    # Check if CA exists
    if not ca_exists(store.path):
        return Failure("CA certificate or key not found. Please initialize the CA first.")

    # Load the certificate
    cert_result = read_ca_cert(store.path)
    if not cert_result:
        return Failure(f"Failed to load CA certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if not cert_deserialize_result:
        return Failure(f"Failed to deserialize certificate: {cert_deserialize_result.error}")

    cert = cert_deserialize_result.unwrap()

    # Extract information from certificate
    subject = cert.subject
    subject_info = {}

    for attr in subject:
        attr_name = attr.oid._name
        attr_value = attr.value
        subject_info[attr_name] = attr_value

    # Build CA info dictionary
    fingerprint_result = cert.fingerprint(hashes.SHA256())
    fingerprint = "SHA256:" + fingerprint_result.hex()

    ca_info = {
        "subject": subject_info,
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "fingerprint": fingerprint,
        "public_key": {
            "type": cert.public_key().__class__.__name__,
        },
    }

    # Calculate days until expiration
    now = datetime.datetime.now(datetime.UTC)
    expiry_date = cert.not_valid_after.replace(tzinfo=datetime.UTC)
    days_remaining = (expiry_date - now).days
    ca_info["days_remaining"] = days_remaining

    return Success(ca_info)


def load_ca_key_cert(store: 'models.Store') -> Result[Tuple[PrivateKeyTypes, x509.Certificate], str]:
    """Load the CA key and certificate.

    Args:
    ----
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with tuple of (private_key, certificate) or error message

    """
    # Check if CA exists
    if not ca_exists(store.path):
        return Failure("CA certificate or key not found. Please initialize the CA first.")

    # Make sure store is unlocked with password
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")
        
    password = store.password

    # Load CA certificate
    cert_result = read_ca_cert(store.path)
    if not cert_result:
        return Failure(f"Failed to load CA certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if not cert_deserialize_result:
        return Failure(f"Failed to deserialize certificate: {cert_deserialize_result.error}")

    cert = cert_deserialize_result.unwrap()

    # Load CA key
    key_result = read_ca_key(store.path, password)
    if not key_result:
        return Failure(f"Failed to load CA key: {key_result.error}")

    key_data = key_result.unwrap()
    key_deserialize_result = deserialize_private_key(key_data, password.encode() if password else None)
    if not key_deserialize_result:
        return Failure(f"Failed to deserialize private key: {key_deserialize_result.error}")

    private_key = key_deserialize_result.unwrap()

    return Success((private_key, cert))
