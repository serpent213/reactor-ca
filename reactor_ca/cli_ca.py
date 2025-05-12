"""Certificate Authority operations for ReactorCA.

This module provides high-level functions for managing the Certificate Authority
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
from pathlib import Path
from typing import Any

from click import Context
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

from reactor_ca.models import (CACertificateParams, Config, Store,
                               SubjectIdentity)
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import (check_ca_files, read_ca_cert, read_ca_key,
                              write_ca_cert, write_ca_key)
from reactor_ca.x509_crypto import (create_ca_certificate,
                                    deserialize_certificate,
                                    deserialize_private_key,
                                    ensure_key_algorithm, generate_key)


def issue_ca(ctx: Context, config: "Config", store: "Store") -> Result[None, str]:
    """Issue a CA certificate. Creates one if it doesn't exist, renews if it does.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked)

    Returns:
    -------
        Result with CA info dict or error message

    """
    console = ctx.obj["console"]
    ca_config = config.ca_config
    if not ca_config:
        return Failure("No CA config provided")
    key_algorithm = ca_config.key_algorithm
    if not store.unlocked:
        return Failure("Store must be unlocked")

    key_present, cert_present = check_ca_files(store)
    if not key_present:
        console.print(f"Generating {key_algorithm} key for CA...")
        key_result = generate_key(key_algorithm)
        if isinstance(key_result, Failure):
            return key_result
        private_key = key_result.unwrap()
    else:
        read_result = read_ca_key(store)
        if isinstance(read_result, Failure):
            return read_result
        private_key = read_result.unwrap()

        # Verify that the existing key matches the algorithm in the config
        key_algorithm_result = ensure_key_algorithm(private_key, key_algorithm)
        if isinstance(key_algorithm_result, Failure):
            return key_algorithm_result

    # Generate self-signed certificate
    ca_params_result = CACertificateParams.from_ca_config(
        ca_config=ca_config,
        private_key=private_key,
    )
    if isinstance(ca_params_result, Failure):
        return ca_params_result
    ca_params = ca_params_result.unwrap()

    cert_result = create_ca_certificate(ca_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create CA certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save key and certificate
    if not key_present:
        key_save_result = write_ca_key(store, private_key)
        if isinstance(key_save_result, Failure):
            return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_save_result = write_ca_cert(store, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    if cert_present:
        console.print("✅ CA certificate renewed successfully")
    else:
        console.print("✅ CA created successfully")

    return Success(None)


def rekey_ca(config: "Config", store: "Store") -> Result[dict[str, Any], str]:
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
        return Failure(
            "CA certificate or key not found. Please initialize the CA first."
        )

    # Make sure we have a password
    if not store.password or not store.unlocked:
        return Failure("Store must be unlocked and have a password set")

    password = store.password

    # Get CA config directly from the Config object
    ca_config = config.ca_config

    # Generate a new key
    key_algorithm = ca_config.key_algorithm
    key_result = generate_key(key_algorithm)
    if isinstance(key_result, Failure):
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

    # Create CA certificate params
    ca_params = CACertificateParams(
        subject_identity=subject_identity,
        private_key=new_ca_key,
        validity_days=validity_days,
        hash_algorithm=ca_config.hash_algorithm,
    )

    cert_result = create_ca_certificate(ca_params)

    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create CA certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save the new certificate and key
    key_bytes_result = new_ca_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_ca_key(store.path, key_bytes_result, password)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_ca_cert(store.path, cert_bytes)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

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
    cert_path: Path,
    key_path: Path,
    config: "Config",
    store: "Store",
    src_password: str | None = None,
) -> Result[dict[str, Any], str]:
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
        return Failure(
            "CA already exists in store. Please remove it first or use a different store."
        )

    # Check if source files exist
    if not cert_path.exists():
        return Failure(f"Certificate file not found: {cert_path}")

    if not key_path.exists():
        return Failure(f"Key file not found: {key_path}")

    # Make sure we have a password in the store for saving
    if not store.password or not store.unlocked:
        return Failure(
            "Store must be unlocked and have a password set for saving imported CA"
        )

    dest_password = store.password

    # Load the certificate
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert_result = deserialize_certificate(cert_data)
        if isinstance(cert_result, Failure):
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
        if isinstance(private_key_result, Failure):
            # Need a password for the source key
            if src_password:
                private_key_result = deserialize_private_key(
                    key_data, src_password.encode()
                )
                if isinstance(private_key_result, Failure):
                    return Failure(
                        f"Failed to decrypt key with provided password: {private_key_result.error}"
                    )
            else:
                return Failure(
                    "Key is password-protected. Please provide a source key password."
                )
    except Exception as e:
        return Failure(f"Error loading key: {str(e)}")

    private_key = private_key_result.unwrap()

    # Verify that the certificate and key match
    public_key_cert = cert.public_key()
    public_key = private_key.public_key()

    if public_key_cert.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ) != public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo):
        return Failure("Certificate and key do not match")

    # Save certificate and key
    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_ca_cert(store.path, cert_bytes)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    key_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_ca_key(store.path, key_bytes, dest_password)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    # Extract metadata for return info
    subject = cert.subject
    common_name = ""
    for attr in subject:
        if attr.oid.dotted_string == "2.5.4.3":  # Common Name
            common_name = str(attr.value) if attr.value is not None else ""

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


def get_ca_info(store: "Store") -> Result[dict[str, Any], str]:
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
        return Failure(
            "CA certificate or key not found. Please initialize the CA first."
        )

    # Load the certificate
    cert_result = read_ca_cert(store.path)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if isinstance(cert_deserialize_result, Failure):
        return Failure(
            f"Failed to deserialize certificate: {cert_deserialize_result.error}"
        )

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
    fingerprint = (
        "SHA256:" + fingerprint_result.hex()
        if isinstance(fingerprint_result, bytes)
        else ""
    )

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
    ca_info["days_remaining"] = str(days_remaining)

    return Success(ca_info)
