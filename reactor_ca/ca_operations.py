"""Certificate Authority operations for ReactorCA."""

import datetime
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
)
from rich.console import Console

from reactor_ca.config import load_ca_config, validate_config
from reactor_ca.crypto import (
    add_standard_extensions,
    create_certificate_builder,
    create_subject_name,
    get_certificate_metadata,
    load_certificate,
    save_private_key,
    sign_certificate,
)
from reactor_ca.models import (
    CAConfig,
    SubjectIdentity,
)
from reactor_ca.store import Store

console = Console()

# Constants for expiration warnings
EXPIRY_CRITICAL = 30  # days
EXPIRY_WARNING = 90  # days

# Hash algorithm mapping
HASH_ALGORITHMS: dict[str, Callable[[], hashes.SHA256 | hashes.SHA384 | hashes.SHA512]] = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

# Default hash algorithm
DEFAULT_HASH_ALGORITHM = "SHA256"


def get_hash_algorithm(algorithm_name: str | None = None) -> hashes.SHA256 | hashes.SHA384 | hashes.SHA512:
    """Get a hash algorithm instance by name."""
    if algorithm_name is None:
        algorithm_name = DEFAULT_HASH_ALGORITHM

    algorithm_name = algorithm_name.upper()
    if algorithm_name not in HASH_ALGORITHMS:
        console.print(
            f"[yellow]Warning:[/yellow] Unknown hash algorithm '{algorithm_name}', using {DEFAULT_HASH_ALGORITHM}"
        )
        algorithm_name = DEFAULT_HASH_ALGORITHM

    return HASH_ALGORITHMS[algorithm_name]()


def generate_key(key_algorithm: str = "RSA4096") -> PrivateKeyTypes:
    """Generate a new private key with the specified algorithm.

    Args:
    ----
        key_algorithm: Combined algorithm and size string (e.g., "RSA2048", "ECP256", "ED25519")

    Returns:
    -------
        A new private key of the specified type.

    """
    key_algorithm = key_algorithm.upper()

    # RSA key algorithms
    if key_algorithm == "RSA2048":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_algorithm == "RSA3072":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    elif key_algorithm == "RSA4096":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
    # EC key algorithms
    elif key_algorithm == "ECP256":
        curve: ec.EllipticCurve = ec.SECP256R1()
        return ec.generate_private_key(curve=curve)
    elif key_algorithm == "ECP384":
        curve = ec.SECP384R1()
        return ec.generate_private_key(curve=curve)
    elif key_algorithm == "ECP521":
        curve = ec.SECP521R1()
        return ec.generate_private_key(curve=curve)
    # Edwards curve algorithms
    elif key_algorithm == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()
    elif key_algorithm == "ED448":
        return ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported key algorithm: {key_algorithm}")


def generate_ca_cert(
    private_key: PrivateKeyTypes, ca_config: CAConfig, validity_days: int = 3650
) -> x509.Certificate:
    """Generate a self-signed CA certificate."""
    # Create subject identity using the CA config
    subject_identity = SubjectIdentity(
        common_name=ca_config.common_name,
        organization=ca_config.organization,
        organization_unit=ca_config.organization_unit,
        country=ca_config.country,
        state=ca_config.state,
        locality=ca_config.locality,
        email=ca_config.email,
    )

    # Convert to x509.Name using the create_subject_name function
    subject = issuer = create_subject_name(subject_identity)

    # Get the hash algorithm from the config or use default
    hash_algorithm_name = ca_config.hash_algorithm
    hash_algorithm = get_hash_algorithm(hash_algorithm_name)

    # Get public key
    public_key = private_key.public_key()

    # Create certificate builder with standard fields
    cert_builder = create_certificate_builder(
        subject=subject, issuer=issuer, public_key=public_key, validity_days=validity_days
    )

    # Add standard extensions for CA certificate
    cert_builder = add_standard_extensions(cert_builder, is_ca=True)

    # Sign the certificate
    return sign_certificate(cert_builder, private_key, hash_algorithm)


def verify_key_algorithm(key: PrivateKeyTypes, expected_algorithm: str) -> bool:
    """Verify that a key matches the expected algorithm and size.

    Args:
    ----
        key: The private key to verify
        expected_algorithm: The expected algorithm identifier (e.g., 'RSA4096', 'ECP256')

    Returns:
    -------
        True if the key matches the expected algorithm, False otherwise

    """
    expected_algorithm = expected_algorithm.upper()

    # Determine the actual key algorithm
    actual_algorithm = _determine_key_algorithm(key)

    # Compare with expected algorithm
    if actual_algorithm != expected_algorithm:
        console.print(
            f"[bold red]Error:[/bold red] Key algorithm mismatch. "
            f"Expected {expected_algorithm}, but found {actual_algorithm}"
        )
        return False

    return True


def issue_ca(store: Store | None = None) -> None:
    """Issue a CA certificate. Creates one if it doesn't exist, renews if it does.

    Args:
    ----
        store: Optional Store instance. If None, a default Store is created.

    """
    from reactor_ca.store import get_store

    # If store is not provided, create a default one
    if store is None:
        store = get_store()

    # Validate configuration first
    ca_config_path = store.config.ca_config_path

    valid, errors = validate_config(ca_config_path, "ca_config_schema.yaml")
    if not valid:
        console.print("[bold red]Error:[/bold red] Configuration validation failed:")
        for error in errors:
            console.print(f"  - {error}")
        return

    # Initialize store
    store.init()

    # Check if CA already exists
    ca_cert_path = store.get_ca_cert_path()
    ca_key_path = store.get_ca_key_path()
    ca_exists = store.ca_cert_exists() or store.ca_key_exists()

    # Load config
    try:
        ca_config = load_ca_config(ca_config_path)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load CA configuration: {e}")
        return

    # Get expected key algorithm from config
    key_algorithm = ca_config.key_algorithm

    if not ca_exists:
        # Creating a new CA
        if ca_exists:  # This check is for situations where files might be changed while processing
            if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
                return

        # Unlock the store with confirmation for new key
        unlock_success = store.unlock(ca_init=True)

        if not unlock_success and ca_config.password.min_length > 0:
            return

        # Generate key
        console.print(f"Generating {key_algorithm} key...")
        private_key = generate_key(key_algorithm=key_algorithm)

        # Generate self-signed certificate
        validity_days = ca_config.validity.to_days()
        console.print(f"Generating self-signed CA certificate valid for {validity_days} days...")
        cert = generate_ca_cert(private_key, ca_config, validity_days)

        # Save encrypted key and certificate
        ca_key_path = store.save_ca_key(private_key)

        ca_cert_path = store.save_ca_cert(cert)

        console.print("✅ CA created successfully")
        console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")
        console.print(f"   Private key (encrypted): [bold]{ca_key_path}[/bold]")

        # Inventory is automatically updated by store.save_ca_cert()
        console.print("📋 Inventory initialized")
    else:
        # Renewing existing CA certificate

        # Unlock the store
        if not store.unlock():
            return

        # Load the CA key
        try:
            ca_key = store.load_ca_key()
            if not ca_key:
                console.print("[bold red]Error:[/bold red] Could not load CA key")
                return
        except Exception as e:
            console.print(f"[bold red]Error loading CA key:[/bold red] {str(e)}")
            return

        # Verify that the existing key matches the algorithm in the config
        if not verify_key_algorithm(ca_key, key_algorithm):
            return

        # Generate new certificate with existing key
        validity_days = ca_config.validity.to_days()
        console.print(f"Generating new CA certificate valid for {validity_days} days...")
        new_ca_cert = generate_ca_cert(ca_key, ca_config, validity_days)

        # Save the new certificate
        ca_cert_path = store.save_ca_cert(new_ca_cert)

        console.print("✅ CA certificate renewed successfully")
        console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")

        # Inventory is automatically updated by store.save_ca_cert()
        console.print("📋 Inventory updated")


def rekey_ca(store: Store | None = None) -> None:
    """Generate a new key and renew the CA certificate.

    Args:
    ----
        store: Optional Store instance. If None, a default Store is created.

    """
    from reactor_ca.store import get_store

    # If store is not provided, create a default one
    if store is None:
        store = get_store()
    # Validate configuration first
    ca_config_path = store.config.ca_config_path
    valid, errors = validate_config(ca_config_path, "ca_config_schema.yaml")
    if not valid:
        console.print("[bold red]Error:[/bold red] Configuration validation failed:")
        for error in errors:
            console.print(f"  - {error}")
        return

    # Initialize store
    store.init()

    # Check if CA exists
    if not store.ca_cert_exists() or not store.ca_key_exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        return

    # Unlock the store
    if not store.unlock():
        return

    # Load config
    try:
        ca_config = load_ca_config(ca_config_path)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load CA configuration: {e}")
        console.print(
            f"Config path: {ca_config_path}, Content: "
            + f"{open(ca_config_path).read() if ca_config_path.exists() else 'file not found'}"
        )
        return

    # Generate a new key
    key_algorithm = ca_config.key_algorithm

    console.print(f"Generating new {key_algorithm} key...")
    new_ca_key = generate_key(key_algorithm=key_algorithm)

    # Generate a new certificate with the new key
    validity_days = ca_config.validity.to_days()
    console.print(f"Generating new CA certificate with new key (valid for {validity_days} days)...")

    # Create a new CA certificate
    new_ca_cert = generate_ca_cert(new_ca_key, ca_config, validity_days)

    # Save the new certificate and key
    ca_cert_path = store.save_ca_cert(new_ca_cert)
    ca_key_path = store.save_ca_key(new_ca_key)

    console.print("✅ CA rekeyed successfully")
    console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{ca_key_path}[/bold]")

    # Inventory is automatically updated by store.save_ca_cert()
    console.print("📋 Inventory updated")


def _validate_ca_import_paths(cert_path: Path, key_path: Path, store: Store) -> tuple[bool, Path, Path, Path, Path]:
    """Validate paths for CA import and check if CA exists.

    Args:
    ----
        cert_path: Path to the certificate file
        key_path: Path to the key file
        store: Store instance for path resolution

    Returns:
    -------
        A tuple containing (success, src_cert_path, src_key_path, ca_cert_dest, ca_key_dest)

    """
    ca_cert_dest = store.get_ca_cert_path()
    ca_key_dest = store.get_ca_key_path()

    if ca_cert_dest.exists() or ca_key_dest.exists():
        if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
            return False, Path(), Path(), ca_cert_dest, ca_key_dest

    # Check if source files exist
    if not cert_path.exists():
        console.print(f"[bold red]Error:[/bold red] Certificate file not found: {cert_path}")
        return False, Path(), Path(), ca_cert_dest, ca_key_dest

    if not key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Key file not found: {key_path}")
        return False, Path(), Path(), ca_cert_dest, ca_key_dest

    # Create certificate directories
    store.ensure_directory_exists(ca_cert_dest.parent)

    return True, cert_path, key_path, ca_cert_dest, ca_key_dest


def _load_and_validate_cert(src_cert_path: Path) -> tuple[bool, x509.Certificate | None, SubjectIdentity]:
    """Load and validate a certificate.

    Returns
    -------
        A tuple containing (success, certificate, certificate_metadata)

    """
    try:
        cert = load_certificate(src_cert_path)
    except Exception as e:
        console.print(f"[bold red]Error loading certificate:[/bold red] {str(e)}")
        return False, None, SubjectIdentity(common_name="")

    # Extract certificate metadata using utility function (returns SubjectIdentity)
    cert_metadata = get_certificate_metadata(cert)

    console.print("📄 Extracted metadata from certificate:")
    console.print(f"   Common Name: [bold]{cert_metadata.common_name}[/bold]")
    console.print(f"   Organization: [bold]{cert_metadata.organization}[/bold]")
    console.print(f"   Country: [bold]{cert_metadata.country}[/bold]")

    return True, cert, cert_metadata


def _load_and_validate_key(
    src_key_path: Path, cert: x509.Certificate
) -> tuple[bool, PrivateKeyTypes | None, str | None]:
    """Load and validate a private key, ensuring it matches the certificate.

    Returns
    -------
        A tuple containing (success, private_key, source_password)

    """
    try:
        with open(src_key_path, "rb") as f:
            key_data = f.read()

        # Try to load it without password first
        try:
            private_key = load_pem_private_key(key_data, password=None)
            src_password = None
        except (TypeError, ValueError):
            # If that fails, prompt for the source key password
            src_password = click.prompt("Enter source key password", hide_input=True, default="", show_default=False)
            try:
                private_key = load_pem_private_key(key_data, password=src_password.encode() if src_password else None)
            except Exception as e:
                console.print(f"[bold red]Error decrypting source key:[/bold red] {str(e)}")
                return False, None, None
    except Exception as e:
        console.print(f"[bold red]Error loading key:[/bold red] {str(e)}")
        return False, None, None

    # Verify that the certificate and key match
    cert_public_key = cert.public_key()
    key_public_key = private_key.public_key()

    if not _verify_key_matches_cert(cert_public_key, key_public_key):
        return False, None, None

    console.print("✅ Verified that certificate and key match")
    return True, private_key, src_password


def _verify_key_matches_cert(cert_public_key: PublicKeyTypes, key_public_key: PublicKeyTypes) -> bool:
    """Verify that a certificate and key match."""
    # Check key type and use appropriate comparison method
    if isinstance(cert_public_key, rsa.RSAPublicKey) and isinstance(key_public_key, rsa.RSAPublicKey):
        # For RSA keys, compare the public_numbers attributes
        cert_public_numbers = cert_public_key.public_numbers()
        key_public_numbers = key_public_key.public_numbers()

        if cert_public_numbers.n != key_public_numbers.n or cert_public_numbers.e != key_public_numbers.e:
            console.print("[bold red]Error:[/bold red] Certificate and key do not match")
            return False
    else:
        # For all other key types (including EC), use a more general comparison
        from cryptography.hazmat.primitives.serialization import PublicFormat

        if cert_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ) != key_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo):
            console.print("[bold red]Error:[/bold red] Certificate and key do not match")
            return False

    return True


def _determine_key_algorithm(private_key: PrivateKeyTypes) -> str:
    """Determine the algorithm used by a private key."""
    # Define key size constants
    rsa_key_size_2048 = 2048
    rsa_key_size_3072 = 3072
    rsa_key_size_4096 = 4096

    if isinstance(private_key, rsa.RSAPrivateKey):
        key_size = private_key.key_size
        if key_size == rsa_key_size_2048:
            return "RSA2048"
        elif key_size == rsa_key_size_3072:
            return "RSA3072"
        elif key_size == rsa_key_size_4096:
            return "RSA4096"
        else:
            return "RSA4096"  # Default to RSA4096 for unknown sizes
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = private_key.curve.name
        if "secp256r1" in curve_name.lower():
            return "ECP256"
        elif "secp384r1" in curve_name.lower():
            return "ECP384"
        elif "secp521r1" in curve_name.lower():
            return "ECP521"
        else:
            return "ECP256"  # Default to ECP256 for unknown curves
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        return "ED25519"
    elif isinstance(private_key, ed448.Ed448PrivateKey):
        return "ED448"
    else:
        return "RSA4096"  # Default to RSA4096 for unknown key types


def _handle_config_for_imported_ca(cert_metadata: SubjectIdentity, key_algorithm: str, store: Store) -> bool:
    """Create or update configuration based on imported CA metadata.

    Args:
    ----
        cert_metadata: Certificate metadata to use for config
        key_algorithm: Key algorithm to set in config
        store: Store instance for path resolution

    Returns:
    -------
        True if configuration was successfully handled, False otherwise

    """
    from reactor_ca.config import (
        create_default_config,
        load_yaml_file,
        update_config_with_metadata,
        write_config_file,
    )

    ca_config_path = store.config.ca_config_path
    config_exists = ca_config_path.exists()

    if not config_exists:
        console.print("📝 No CA configuration found. Creating new configuration from certificate metadata...")

        # Create default config with metadata from certificate
        create_default_config(store.config)

        try:
            # Load the created config
            config = load_yaml_file(ca_config_path)

            # Update config with metadata from certificate
            update_config_with_metadata(config, cert_metadata, key_algorithm, fallback_to_default=True)

            # Write updated config
            write_config_file(config, ca_config_path, "ca")
            console.print("✅ Created and updated configuration with certificate metadata")
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/bold yellow] Failed to update config with metadata: {str(e)}")
            return False
    else:
        # Config exists, ask if user wants to update it
        console.print("📄 Existing CA configuration found.")
        if click.confirm(
            "Do you want to update configuration with metadata from the imported certificate?", default=True
        ):
            try:
                # Load existing config
                config = load_yaml_file(ca_config_path)

                # Update only non-empty fields from certificate
                update_config_with_metadata(config, cert_metadata, key_algorithm)

                # Write updated config
                write_config_file(config, ca_config_path, "ca")
                console.print("✅ Updated configuration with certificate metadata")
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/bold yellow] Failed to update config with metadata: {str(e)}")
                return False

    return True


def _complete_ca_import(
    cert: x509.Certificate,
    private_key: PrivateKeyTypes,
    src_cert_path: Path,
    ca_cert_dest: Path,
    ca_key_dest: Path,
    store: Store | None = None,
) -> bool:
    """Complete the CA import by saving files and updating inventory.

    Args:
    ----
        cert: Certificate object
        private_key: Private key object
        src_cert_path: Source certificate path
        ca_cert_dest: Destination path for CA certificate
        ca_key_dest: Destination path for CA key
        store: Optional Store instance. If None, a default Store is created.

    Returns:
    -------
        True if import was successful, False otherwise

    """
    from reactor_ca.store import get_store

    # If store is not provided, create a default one
    if store is None:
        store = get_store()

    # Get password for encrypting the key
    if not store.unlock():
        return False
    dest_password = store._password

    # Encrypt and save the key using utility function
    save_private_key(private_key, ca_key_dest, dest_password.encode() if dest_password else None)

    # Read and save the certificate
    with open(src_cert_path, "rb") as f:
        cert_data = f.read()

    with open(ca_cert_dest, "wb") as f:
        f.write(cert_data)

    console.print("✅ CA imported successfully")
    console.print(f"   Certificate: [bold]{ca_cert_dest}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{ca_key_dest}[/bold]")

    # Update inventory
    store.update_inventory_for_cert(hostname="ca", cert=cert, rekeyed=True, renewal_count_increment=0)
    console.print("📋 Inventory updated")

    return True


def import_ca(cert_path: Path, key_path: Path, store: Store | None = None) -> bool:
    """Import an existing CA certificate and key.

    Args:
    ----
        cert_path: Path to the certificate file
        key_path: Path to the key file
        store: Optional Store instance. If None, a default Store is created.

    """
    from reactor_ca.store import get_store

    # If store is not provided, create a default one
    if store is None:
        store = get_store()

    # Validate paths and check if CA exists
    success, src_cert_path, src_key_path, ca_cert_dest, ca_key_dest = _validate_ca_import_paths(
        cert_path, key_path, store
    )
    if not success:
        return False

    # Load and validate the certificate
    success, cert, cert_metadata = _load_and_validate_cert(src_cert_path)
    if not success or cert is None:
        return False

    # Load and validate the key
    success, private_key, _ = _load_and_validate_key(src_key_path, cert)
    if not success or private_key is None:
        return False

    # Determine key algorithm
    key_algorithm = _determine_key_algorithm(private_key)

    # Handle configuration
    if not _handle_config_for_imported_ca(cert_metadata, key_algorithm, store):
        return False

    # Complete the import process
    return _complete_ca_import(cert, private_key, src_cert_path, ca_cert_dest, ca_key_dest, store)


def show_ca_info(json_output: bool = False, store: Store | None = None) -> None:
    """Show information about the CA certificate.

    Args:
    ----
        json_output: Whether to output in JSON format
        store: Optional Store instance. If None, a default Store is created.

    """
    from reactor_ca.store import get_store

    # If store is not provided, create a default one
    if store is None:
        store = get_store()
    # Check if CA exists
    ca_cert_path = store.get_ca_cert_path()
    if not ca_cert_path.exists():
        console.print("[bold red]Error:[/bold red] CA certificate not found. Please initialize the CA first.")
        return

    # Load the certificate
    try:
        cert = load_certificate(ca_cert_path)
    except Exception as e:
        console.print(f"[bold red]Error loading certificate:[/bold red] {str(e)}")
        return

    # Extract information using utility function
    subject_identity = get_certificate_metadata(cert)

    # Build CA info dictionary
    ca_info: dict[str, Any] = {
        "subject": {
            "common_name": subject_identity.common_name,
            "organization": subject_identity.organization,
            "organization_unit": subject_identity.organization_unit,
            "country": subject_identity.country,
            "state": subject_identity.state,
            "locality": subject_identity.locality,
            "email": subject_identity.email,
        },
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
        "public_key": {
            "type": cert.public_key().__class__.__name__,
        },
    }

    # Calculate days until expiration
    now = datetime.datetime.now(datetime.UTC)
    expiry_date = cert.not_valid_after.replace(tzinfo=datetime.UTC)
    days_remaining = (expiry_date - now).days

    ca_info["days_remaining"] = days_remaining

    # Display the information
    if json_output:
        import json

        console.print(json.dumps(ca_info, indent=2))
    else:
        console.print("[bold]CA Certificate Information[/bold]")
        console.print(f"Subject: {subject_identity.common_name}")
        console.print(f"Organization: {subject_identity.organization}")
        console.print(f"Organizational Unit: {subject_identity.organization_unit}")
        console.print(f"Country: {subject_identity.country}")
        console.print(f"State/Province: {subject_identity.state}")
        console.print(f"Locality: {subject_identity.locality}")
        console.print(f"Email: {subject_identity.email}")
        console.print(f"Serial: {ca_info['serial']}")
        console.print(f"Valid From: {ca_info['not_before']}")
        console.print(f"Valid Until: {ca_info['not_after']}")

        # Format days remaining with color based on how soon it expires
        if days_remaining < 0:
            console.print(f"Days Remaining: [bold red]{days_remaining} (expired)[/bold red]")
        elif days_remaining < EXPIRY_CRITICAL:
            console.print(f"Days Remaining: [bold orange]{days_remaining}[/bold orange]")
        elif days_remaining < EXPIRY_WARNING:
            console.print(f"Days Remaining: [bold yellow]{days_remaining}[/bold yellow]")
        else:
            console.print(f"Days Remaining: {days_remaining}")

        console.print(f"Fingerprint: {ca_info['fingerprint']}")
        console.print(f"Public Key Type: {ca_info['public_key']['type']}")
