"""Certificate Authority operations for ReactorCA."""

import datetime
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from rich.console import Console

from reactor_ca.config_validator import validate_config_before_operation
from reactor_ca.models import (
    SubjectIdentity,
)
from reactor_ca.paths import CA_DIR, CONFIG_DIR
from reactor_ca.utils import (
    add_standard_extensions,
    calculate_validity_days,
    create_certificate_builder,
    create_default_config,
    create_subject_name,
    ensure_directory_exists,
    get_certificate_metadata,
    get_password,
    load_certificate,
    load_config,
    load_inventory,
    save_certificate,
    save_inventory,
    save_private_key,
    sign_certificate,
    update_inventory_for_cert,
)

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


def encrypt_key(private_key: PrivateKeyTypes, password: str | None) -> bytes:
    """Encrypt a private key with a password."""
    # All PrivateKeyTypes implement the private_bytes method, but typing doesn't capture that
    # We don't need type: ignore as PrivateKeyTypes should have the private_bytes method
    if not password:
        # Use no encryption if password is empty
        return private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )


def decrypt_key(key_path: Path, password: str | None) -> PrivateKeyTypes:
    """Decrypt a private key file with a password."""
    with open(key_path, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=password.encode() if password else None)


def generate_ca_cert(
    private_key: PrivateKeyTypes, config: dict[str, Any], validity_days: int = 3650
) -> x509.Certificate:
    """Generate a self-signed CA certificate."""
    # Create subject identity using the CA config
    subject_identity = SubjectIdentity(
        common_name=config["ca"]["common_name"],
        organization=config["ca"]["organization"],
        organization_unit=config["ca"]["organization_unit"],
        country=config["ca"]["country"],
        state=config["ca"]["state"],
        locality=config["ca"]["locality"],
        email=config["ca"]["email"],
    )

    # Convert to x509.Name using the create_subject_name function
    subject = issuer = create_subject_name(subject_identity)

    # Get the hash algorithm from the config or use default
    hash_algorithm_name = config["ca"].get("hash_algorithm", DEFAULT_HASH_ALGORITHM)
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


def issue_ca() -> None:
    """Issue a CA certificate. Creates one if it doesn't exist, renews if it does."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before issuing the CA certificate."
        )
        return

    # Check if CA already exists

    ca_cert_path = CA_DIR / "ca.crt"
    ca_key_path = CA_DIR / "ca.key.enc"
    ca_exists = ca_cert_path.exists() or ca_key_path.exists()

    # Load config
    config = load_config()

    # Get expected key algorithm from config
    key_algorithm = config["ca"]["key_algorithm"]

    # Create certificate directories
    ensure_directory_exists(CA_DIR)

    if not ca_exists:
        # Creating a new CA
        if ca_exists:  # This check is for situations where files might be changed while processing
            if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
                return

        # Get password with confirmation for new key
        password = get_password(ca_init=True)
        if not password and config["ca"]["password"]["min_length"] > 0:
            return

        # Generate key
        console.print(f"Generating {key_algorithm} key...")
        private_key = generate_key(key_algorithm=key_algorithm)

        # Generate self-signed certificate
        validity_days = calculate_validity_days(config["ca"]["validity"])
        console.print(f"Generating self-signed CA certificate valid for {validity_days} days...")
        cert = generate_ca_cert(private_key, config, validity_days)

        # Save encrypted key and certificate
        save_private_key(private_key, ca_key_path, password.encode() if password else None)
        save_certificate(cert, ca_cert_path)

        console.print("✅ CA created successfully")
        console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")
        console.print(f"   Private key (encrypted): [bold]{ca_key_path}[/bold]")

        # Initialize inventory
        inventory = {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {
                "serial": format(cert.serial_number, "x"),
                "not_after": cert.not_valid_after.isoformat(),
                "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
            },
            "hosts": [],
        }
        save_inventory(inventory)
        console.print("📋 Inventory initialized")
    else:
        # Renewing existing CA certificate
        # Get password
        password = get_password()
        if not password:
            return

        # Decrypt the CA key
        try:
            ca_key = decrypt_key(ca_key_path, password)
        except Exception as e:
            console.print(f"[bold red]Error decrypting CA key:[/bold red] {str(e)}")
            return

        # Verify that the existing key matches the algorithm in the config
        if not verify_key_algorithm(ca_key, key_algorithm):
            console.print(
                "[bold red]Error:[/bold red] The existing key algorithm does not match the configuration. "
                "Use 'ca rekey' to generate a new key with the configured algorithm."
            )
            return

        # Generate a new certificate with the same key
        validity_days = calculate_validity_days(config["ca"]["validity"])
        console.print(f"Renewing CA certificate with the existing key (valid for {validity_days} days)...")

        # Create a new CA certificate
        new_ca_cert = generate_ca_cert(ca_key, config, validity_days)

        # Save the new certificate
        save_certificate(new_ca_cert, ca_cert_path)

        console.print("✅ CA certificate renewed successfully")
        console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")

        # Update inventory
        inventory = load_inventory()
        inventory["ca"] = {
            "serial": format(new_ca_cert.serial_number, "x"),
            "not_after": new_ca_cert.not_valid_after.isoformat(),
            "fingerprint": "SHA256:" + new_ca_cert.fingerprint(hashes.SHA256()).hex(),
        }
        inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()
        save_inventory(inventory)
        console.print("📋 Inventory updated")


def rekey_ca() -> None:
    """Generate a new key and renew the CA certificate."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before rekeying the CA."
        )
        return

    # Check if CA exists
    ca_cert_path = CA_DIR / "ca.crt"
    ca_key_path = CA_DIR / "ca.key.enc"

    if not ca_cert_path.exists() or not ca_key_path.exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        return

    # Get password
    password = get_password()
    if not password:
        return

    # Decrypt the old CA key to validate password
    try:
        decrypt_key(ca_key_path, password)
    except Exception as e:
        console.print(f"[bold red]Error decrypting CA key:[/bold red] {str(e)}")
        return

    # Load config
    config = load_config()

    # Generate a new key
    key_algorithm = config["ca"]["key_algorithm"]

    console.print(f"Generating new {key_algorithm} key...")
    new_ca_key = generate_key(key_algorithm=key_algorithm)

    # Generate a new certificate with the new key
    validity_days = calculate_validity_days(config["ca"]["validity"])
    console.print(f"Generating new CA certificate with new key (valid for {validity_days} days)...")

    # Create a new CA certificate
    new_ca_cert = generate_ca_cert(new_ca_key, config, validity_days)

    # Save the new certificate and key
    save_certificate(new_ca_cert, ca_cert_path)
    save_private_key(new_ca_key, ca_key_path, password.encode() if password else None)

    console.print("✅ CA rekeyed successfully")
    console.print(f"   Certificate: [bold]{ca_cert_path}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{ca_key_path}[/bold]")

    # Update inventory
    inventory = load_inventory()
    inventory["ca"] = {
        "serial": format(new_ca_cert.serial_number, "x"),
        "not_after": new_ca_cert.not_valid_after.isoformat(),
        "fingerprint": "SHA256:" + new_ca_cert.fingerprint(hashes.SHA256()).hex(),
    }
    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")


def _validate_ca_import_paths(cert_path: Path, key_path: Path) -> tuple[bool, Path, Path, Path, Path]:
    """Validate paths for CA import and check if CA exists.

    Returns
    -------
        A tuple containing (success, src_cert_path, src_key_path, ca_cert_dest, ca_key_dest)

    """
    ca_cert_dest = CA_DIR / "ca.crt"
    ca_key_dest = CA_DIR / "ca.key.enc"

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
    ensure_directory_exists(CA_DIR)

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


def _handle_config_for_imported_ca(cert_metadata: SubjectIdentity, key_algorithm: str) -> bool:
    """Create or update configuration based on imported CA metadata."""
    config_path = CONFIG_DIR / "ca.yaml"
    config_exists = config_path.exists()

    if not config_exists:
        console.print("📝 No CA configuration found. Creating new configuration from certificate metadata...")

        # Create default config with metadata from certificate

        create_default_config()

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)

            # Update config with metadata from certificate
            _update_config_with_metadata(config, cert_metadata, key_algorithm, fallback_to_default=True)

            # Write updated config
            _write_config_file(config_path, config)
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
                with open(config_path) as f:
                    config = yaml.safe_load(f)

                # Update only non-empty fields from certificate
                _update_config_with_metadata(config, cert_metadata, key_algorithm)

                # Write updated config
                _write_config_file(config_path, config)
                console.print("✅ Updated configuration with certificate metadata")
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/bold yellow] Failed to update config with metadata: {str(e)}")
                return False

    return True


def _update_config_with_metadata(
    config: dict, cert_metadata: SubjectIdentity, key_algorithm: str, fallback_to_default: bool = False
) -> None:
    """Update configuration with certificate metadata."""

    # Helper function to update a config field if the metadata exists
    def update_field(config_field: str, metadata_field: str) -> None:
        metadata_value = getattr(cert_metadata, metadata_field)
        if fallback_to_default:
            config["ca"][config_field] = metadata_value or config["ca"][config_field]
        elif metadata_value:
            config["ca"][config_field] = metadata_value

    update_field("common_name", "common_name")
    update_field("organization", "organization")
    update_field("organization_unit", "organization_unit")
    update_field("country", "country")
    update_field("state", "state")
    update_field("locality", "locality")
    update_field("email", "email")

    # Always update key algorithm
    config["ca"]["key_algorithm"] = key_algorithm


def _write_config_file(config_path: Path, config: dict) -> None:
    """Write configuration to file with standard header."""
    with open(config_path, "w") as f:
        f.write("# ReactorCA Configuration\n")
        f.write("# This file contains settings for the Certificate Authority\n")
        f.write("# It is safe to modify this file directly\n\n")
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _complete_ca_import(
    cert: x509.Certificate, private_key: PrivateKeyTypes, src_cert_path: Path, ca_cert_dest: Path, ca_key_dest: Path
) -> bool:
    """Complete the CA import by saving files and updating inventory."""
    # Get password for encrypting the key
    dest_password = get_password()
    if not dest_password:
        return False

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
    inventory = load_inventory()
    inventory = update_inventory_for_cert(
        inventory=inventory, hostname="ca", cert=cert, rekeyed=True, renewal_count_increment=0
    )

    # Additional CA-specific inventory information
    inventory["ca"] = {
        "serial": format(cert.serial_number, "x"),
        "not_after": cert.not_valid_after.isoformat(),
        "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
    }

    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def import_ca(cert_path: Path, key_path: Path) -> bool:
    """Import an existing CA certificate and key."""
    # Validate paths and check if CA exists
    success, src_cert_path, src_key_path, ca_cert_dest, ca_key_dest = _validate_ca_import_paths(cert_path, key_path)
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
    if not _handle_config_for_imported_ca(cert_metadata, key_algorithm):
        return False

    # Complete the import process
    return _complete_ca_import(cert, private_key, src_cert_path, ca_cert_dest, ca_key_dest)


def show_ca_info(json_output: bool = False) -> None:
    """Show information about the CA certificate."""
    # Check if CA exists
    from reactor_ca.paths import CA_DIR

    ca_cert_path = CA_DIR / "ca.crt"

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
