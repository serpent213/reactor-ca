"""Certificate Authority operations for ReactorCA.

This module provides high-level functions for managing the Certificate Authority
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
from pathlib import Path
from typing import Any

from click import Context
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from reactor_ca.defaults import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS
from reactor_ca.models import CACertificateParams, Config, Store
from reactor_ca.paths import get_ca_cert_path, get_ca_key_path
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import check_ca_files, read_ca_cert, read_ca_key, unlock, write_ca_cert, write_ca_key
from reactor_ca.x509_crypto import (
    create_ca_certificate,
    deserialize_certificate,
    deserialize_private_key,
    ensure_key_algorithm,
    generate_key,
)
from cryptography import x509


def issue_ca(ctx: Context, config: "Config", store: "Store", password: str) -> Result[None, str]:
    """Issue a CA certificate. Creates one if it doesn't exist, renews if it does.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object for path info
        password: The master password for encryption.

    Returns:
    -------
        Result with None or error message

    """
    console = ctx.obj["console"]
    ca_config = config.ca_config
    if not ca_config:
        return Failure("No CA config provided")
    key_algorithm = ca_config.key_algorithm

    key_present, cert_present = check_ca_files(store)

    # For CA creation, we only unlock if a key already exists (for renewal)
    if key_present:
        unlock_result = unlock(store, password)
        if isinstance(unlock_result, Failure):
            return unlock_result
        unlocked_store = unlock_result.unwrap()
    else:
        # Create a new unlocked store for initial CA creation
        unlocked_store = Store(path=store.path, password=password, unlocked=True)
    if not key_present:
        console.print(f"Generating {key_algorithm} key for CA...")
        key_result = generate_key(key_algorithm)
        if isinstance(key_result, Failure):
            return key_result
        private_key = key_result.unwrap()
    else:
        read_result = read_ca_key(unlocked_store, password)
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
        key_save_result = write_ca_key(unlocked_store, private_key)
        if isinstance(key_save_result, Failure):
            return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_save_result = write_ca_cert(unlocked_store, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    if cert_present:
        console.print("✅ CA certificate renewed successfully")
    else:
        console.print("✅ CA created successfully")

    return Success(None)


def rekey_ca(ctx: Context, config: "Config", store: "Store", password: str) -> Result[None, str]:
    """Generate a new key and renew the CA certificate.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object for path info
        password: The master password.

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    # Unlock the store with the password
    unlock_result = unlock(store, password)
    if isinstance(unlock_result, Failure):
        return unlock_result
    unlocked_store = unlock_result.unwrap()

    # Check if CA exists
    key_present, cert_present = check_ca_files(unlocked_store)
    if not key_present or not cert_present:
        return Failure("CA certificate or key not found. Please initialize the CA first.")

    # Get CA config directly from the Config object
    ca_config = config.ca_config
    if not ca_config:
        return Failure("No CA configuration found")

    # Generate a new key
    console.print(f"Generating {ca_config.key_algorithm} key for CA...")
    key_result = generate_key(ca_config.key_algorithm)
    if isinstance(key_result, Failure):
        return key_result
    new_ca_key = key_result.unwrap()

    # Create CA certificate params from config
    ca_params_result = CACertificateParams.from_ca_config(
        ca_config=ca_config,
        private_key=new_ca_key,
    )
    if isinstance(ca_params_result, Failure):
        return ca_params_result
    ca_params = ca_params_result.unwrap()

    # Create CA certificate
    cert_result = create_ca_certificate(ca_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create CA certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save the new certificate and key
    key_save_result = write_ca_key(unlocked_store, new_ca_key)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_save_result = write_ca_cert(unlocked_store, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    # Print success message
    console.print("✅ CA rekeyed successfully")
    console.print(f"   Certificate: [bold]{get_ca_cert_path(store)}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_ca_key_path(store)}[/bold]")

    return Success(None)


def import_ca(
    ctx: Context,
    cert_path: Path,
    key_path: Path,
    config: "Config",
    store: "Store",
    new_password: str,
    src_key_password: str | None = None,
) -> Result[None, str]:
    """Import an existing CA certificate and key.

    Args:
    ----
        ctx: Click context
        cert_path: Path to the certificate file
        key_path: Path to the key file
        config: Config object with loaded configurations
        store: Store object for path info
        new_password: The master password to encrypt the new key with.
        src_key_password: Optional password for the source key.

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    # Check if CA exists in the store
    if any(check_ca_files(store)):
        return Failure("CA already exists in store. Please remove it first or use a different store.")

    # Load the certificate
    try:
        cert_data = cert_path.read_bytes()
        cert_result = deserialize_certificate(cert_data)
        if isinstance(cert_result, Failure):
            return Failure(f"Failed to load certificate: {cert_result.error}")
        cert = cert_result.unwrap()
    except Exception as e:
        return Failure(f"Error loading certificate: {e!s}")

    # Load the private key
    try:
        key_data = key_path.read_bytes()
        private_key_result = deserialize_private_key(key_data, src_key_password)
        if isinstance(private_key_result, Failure):
            if src_key_password:
                return Failure(f"Failed to decrypt key with provided password: {private_key_result.error}")
            return Failure(
                f"Key is password-protected or invalid. Try --key-password. Error: {private_key_result.error}"
            )
        private_key = private_key_result.unwrap()
    except Exception as e:
        return Failure(f"Error loading key: {e!s}")

    # Verify that the certificate and key match
    public_key_cert = cert.public_key()
    public_key = private_key.public_key()
    if public_key_cert.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) != public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ):
        return Failure("Certificate and key do not match")

    # Create an unlocked store with the new password for saving
    unlocked_store = Store(path=store.path, password=new_password, unlocked=True)

    # Save certificate and key, encrypted with the new password
    cert_save_result = write_ca_cert(unlocked_store, cert)
    if isinstance(cert_save_result, Failure):
        return cert_save_result

    key_save_result = write_ca_key(unlocked_store, private_key)
    if isinstance(key_save_result, Failure):
        return key_save_result

    # Print success message
    common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    console.print("✅ CA imported successfully")
    console.print(f"   Certificate: [bold]{get_ca_cert_path(store)}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_ca_key_path(store)}[/bold]")
    console.print(f"   Common Name: [bold]{common_name}[/bold]")

    return Success(None)


def get_ca_info_dict(store: "Store") -> Result[dict[str, Any], str]:
    """Get information about the CA certificate as a dictionary.

    Args:
    ----
        store: Store object containing path information

    Returns:
    -------
        Result with CA info dictionary or error message

    """
    if not check_ca_files(store)[1]:
        return Failure("CA certificate not found. Please initialize the CA first.")

    cert_result = read_ca_cert(store)
    if isinstance(cert_result, Failure):
        return cert_result
    cert = cert_result.unwrap()

    subject_info = {attr.oid._name: attr.value for attr in cert.subject}
    fingerprint = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
    now = datetime.datetime.now(datetime.UTC)
    days_remaining = (cert.not_valid_after_utc - now).days

    ca_info = {
        "subject": subject_info,
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_remaining": days_remaining,
        "fingerprint": fingerprint,
        "public_key": {
            "type": cert.public_key().__class__.__name__,
        },
        "key_present": check_ca_files(store)[0],
    }

    return Success(ca_info)


def get_ca_info(ctx: Context, store: "Store") -> Result[None, str]:
    """Get information about the CA certificate and display it.

    Args:
    ----
        ctx: Click context
        store: Store object containing path information

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    info_result = get_ca_info_dict(store)
    if isinstance(info_result, Failure):
        return info_result
    info = info_result.unwrap()

    console.print("[bold]CA Certificate Information[/bold]")
    for key, value in info["subject"].items():
        console.print(f"{key.replace('_', ' ').title()}: {value}")

    console.print(f"Serial: {info['serial']}")
    console.print(f"Valid From: {info['not_before']}")
    console.print(f"Valid Until: {info['not_after']}")

    days_remaining = info["days_remaining"]
    if days_remaining < 0:
        expiry_style = "bold red"
        expiry_text = f"{days_remaining} (expired)"
    elif days_remaining < EXPIRY_CRITICAL_DAYS:
        expiry_style = "bold red"
        expiry_text = str(days_remaining)
    elif days_remaining < EXPIRY_WARNING_DAYS:
        expiry_style = "bold yellow"
        expiry_text = str(days_remaining)
    else:
        expiry_style = "none"
        expiry_text = str(days_remaining)
    console.print(f"Days Remaining: [{expiry_style}]{expiry_text}[/{expiry_style}]")

    console.print(f"Fingerprint: {info['fingerprint']}")
    console.print(f"Public Key Type: {info['public_key']['type']}")

    key_status = "[bold green]Present[/bold green]" if info["key_present"] else "[bold red]Missing[/bold red]"
    console.print(f"Private Key: {key_status}")

    return Success(None)
