"""Certificate Authority operations for ReactorCA.

This module provides high-level functions for managing the Certificate Authority
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
from pathlib import Path
from typing import Any

from click import Context
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat

from reactor_ca.defaults import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS
from reactor_ca.models import CACertificateParams, Config, Store
from reactor_ca.paths import get_store_ca_cert_path, get_store_ca_key_path
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import check_ca_files, read_ca_cert, read_ca_key, write_ca_cert, write_ca_key
from reactor_ca.x509_crypto import (
    create_ca_certificate,
    deserialize_certificate,
    deserialize_private_key,
    ensure_key_algorithm,
    generate_key,
)


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


def rekey_ca(ctx: Context, config: "Config", store: "Store") -> Result[None, str]:
    """Generate a new key and renew the CA certificate.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    # Check if CA exists
    key_present, cert_present = check_ca_files(store)
    if not key_present or not cert_present:
        return Failure("CA certificate or key not found. Please initialize the CA first.")

    # Make sure we have a password
    if not store.password or not store.unlocked:
        return Failure("Store must be unlocked and have a password set")

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

    # Generate a new certificate with the new key
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
    key_save_result = write_ca_key(store, new_ca_key)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    cert_save_result = write_ca_cert(store, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    # Print success message
    console.print("✅ CA rekeyed successfully")
    console.print(f"   Certificate: [bold]{get_store_ca_cert_path(store)}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_store_ca_key_path(store)}[/bold]")
    console.print("📋 Inventory updated")

    return Success(None)


def import_ca(
    ctx: Context,
    cert_path: Path,
    key_path: Path,
    config: "Config",
    store: "Store",
    src_password: str | None = None,
) -> Result[None, str]:
    """Import an existing CA certificate and key.

    Args:
    ----
        ctx: Click context
        cert_path: Path to the certificate file
        key_path: Path to the key file
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        src_password: Optional password for the source key

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    # Check if CA exists in the store
    key_present, cert_present = check_ca_files(store)
    if key_present or cert_present:
        return Failure("CA already exists in store. Please remove it first or use a different store.")

    # Check if source files exist
    if not cert_path.exists():
        return Failure(f"Certificate file not found: {cert_path}")

    if not key_path.exists():
        return Failure(f"Key file not found: {key_path}")

    # Make sure we have a password in the store for saving
    if not store.password or not store.unlocked:
        return Failure("Store must be unlocked and have a password set for saving imported CA")

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
                private_key_result = deserialize_private_key(key_data, src_password)
                if isinstance(private_key_result, Failure):
                    return Failure(f"Failed to decrypt key with provided password: {private_key_result.error}")
            else:
                return Failure("Key is password-protected. Please provide a source key password.")
    except Exception as e:
        return Failure(f"Error loading key: {str(e)}")

    private_key = private_key_result.unwrap()

    # Verify that the certificate and key match
    public_key_cert = cert.public_key()
    public_key = private_key.public_key()

    if public_key_cert.public_bytes(PublicFormat.SubjectPublicKeyInfo) != public_key.public_bytes(
        PublicFormat.SubjectPublicKeyInfo
    ):
        return Failure("Certificate and key do not match")

    # Save certificate and key
    cert_save_result = write_ca_cert(store, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save CA certificate: {cert_save_result.error}")

    key_save_result = write_ca_key(store, private_key)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save CA key: {key_save_result.error}")

    # Extract common name for output
    subject = cert.subject
    common_name = ""
    for attr in subject:
        if attr.oid.dotted_string == "2.5.4.3":  # Common Name
            common_name = str(attr.value) if attr.value is not None else ""

    # Print success message
    console.print("✅ CA imported successfully")
    console.print(f"   Certificate: [bold]{get_store_ca_cert_path(store)}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_store_ca_key_path(store)}[/bold]")
    if common_name:
        console.print(f"   Common Name: [bold]{common_name}[/bold]")

    return Success(None)


def get_ca_info_dict(store: "Store") -> Result[dict[str, Any], str]:
    """Get information about the CA certificate as a dictionary.

    Args:
    ----
        store: Store object containing path and password information

    Returns:
    -------
        Result with CA info dictionary or error message

    """
    # Check if CA exists
    key_present, cert_present = check_ca_files(store)
    if not cert_present:
        return Failure("CA certificate not found. Please initialize the CA first.")

    # Load the certificate
    cert_result = read_ca_cert(store)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {cert_result.error}")

    cert = cert_result.unwrap()

    # Extract information from certificate
    subject = cert.subject
    subject_info = {}

    for attr in subject:
        attr_name = attr.oid._name
        attr_value = attr.value
        subject_info[attr_name] = attr_value

    # Build fingerprint
    fingerprint_result = cert.fingerprint(hashes.SHA256())
    fingerprint = "SHA256:" + fingerprint_result.hex() if isinstance(fingerprint_result, bytes) else ""

    # Calculate days until expiration
    now = datetime.datetime.now(datetime.UTC)
    expiry_date = cert.not_valid_after.replace(tzinfo=datetime.UTC)
    days_remaining = (expiry_date - now).days

    # Build CA info dictionary
    ca_info = {
        "subject": subject_info,
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "days_remaining": days_remaining,
        "fingerprint": fingerprint,
        "public_key": {
            "type": cert.public_key().__class__.__name__,
        },
        "key_present": key_present,
    }

    return Success(ca_info)


def get_ca_info(ctx: Context, store: "Store") -> Result[None, str]:
    """Get information about the CA certificate and display it.

    Args:
    ----
        ctx: Click context
        store: Store object containing path and password information

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    # Get CA information as dictionary
    info_result = get_ca_info_dict(store)
    if isinstance(info_result, Failure):
        return info_result

    info = info_result.unwrap()
    subject_info = info["subject"]
    days_remaining = info["days_remaining"]
    key_present = info["key_present"]

    # Display CA information
    console.print("[bold]CA Certificate Information[/bold]")

    # Subject information
    common_name = subject_info.get("commonName", "")
    console.print(f"Subject: {common_name}")

    if "organizationName" in subject_info:
        console.print(f"Organization: {subject_info.get('organizationName', '')}")

    if "organizationalUnitName" in subject_info:
        console.print(f"Organizational Unit: {subject_info.get('organizationalUnitName', '')}")

    if "countryName" in subject_info:
        console.print(f"Country: {subject_info.get('countryName', '')}")

    if "stateOrProvinceName" in subject_info:
        console.print(f"State/Province: {subject_info.get('stateOrProvinceName', '')}")

    if "localityName" in subject_info:
        console.print(f"Locality: {subject_info.get('localityName', '')}")

    if "emailAddress" in subject_info:
        console.print(f"Email: {subject_info.get('emailAddress', '')}")

    # Certificate details
    console.print(f"Serial: {info['serial']}")
    console.print(f"Valid From: {info['not_before']}")
    console.print(f"Valid Until: {info['not_after']}")

    # Format days remaining with color based on how soon it expires

    if days_remaining < 0:
        console.print(f"Days Remaining: [bold red]{days_remaining} (expired)[/bold red]")
    elif days_remaining < EXPIRY_CRITICAL_DAYS:
        console.print(f"Days Remaining: [bold red]{days_remaining}[/bold red]")
    elif days_remaining < EXPIRY_WARNING_DAYS:
        console.print(f"Days Remaining: [bold yellow]{days_remaining}[/bold yellow]")
    else:
        console.print(f"Days Remaining: {days_remaining}")

    console.print(f"Fingerprint: {info['fingerprint']}")
    console.print(f"Public Key Type: {info['public_key']['type']}")

    # Show key status
    if key_present:
        console.print("Private Key: [bold green]Present[/bold green]")
    else:
        console.print("Private Key: [bold red]Missing[/bold red]")

    return Success(None)
