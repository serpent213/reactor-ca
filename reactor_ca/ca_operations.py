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
    PrivateKeyTypes,  # Updated from PRIVATE_KEY_TYPES
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID
from rich.console import Console

from reactor_ca.config_validator import validate_config_before_operation
from reactor_ca.utils import (
    calculate_validity_days,
    get_password,
    load_config,
    load_inventory,
    save_inventory,
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


def decrypt_key(key_path: str | Path, password: str | None) -> PrivateKeyTypes:
    """Decrypt a private key file with a password."""
    with open(key_path, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=password.encode() if password else None)


def generate_ca_cert(
    private_key: PrivateKeyTypes, config: dict[str, Any], validity_days: int = 3650
) -> x509.Certificate:
    """Generate a self-signed CA certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, config["ca"]["common_name"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config["ca"]["organization"]),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config["ca"]["organization_unit"]),
            x509.NameAttribute(NameOID.COUNTRY_NAME, config["ca"]["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config["ca"]["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, config["ca"]["locality"]),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, config["ca"]["email"]),
        ]
    )

    # Get the hash algorithm from the config or use default
    hash_algorithm_name = config["ca"].get("hash_algorithm", DEFAULT_HASH_ALGORITHM)
    hash_algorithm = get_hash_algorithm(hash_algorithm_name)

    now = datetime.datetime.now(datetime.UTC)
    # We can help type checking by explicitly typing the builder
    cert_builder = x509.CertificateBuilder()

    # Type checkers can't infer that PrivateKeyTypes has a public_key method
    # but all such types do, so we access it directly
    public_key = private_key.public_key()

    # For typechecking, we need to ensure we're using the correct type
    # The CertificateBuilder.public_key method accepts specific public key types
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    # Using an assertion to help mypy understand the type
    assert isinstance(
        public_key,
        (
            RSAPublicKey
            | DSAPublicKey
            | EllipticCurvePublicKey
            | Ed25519PublicKey
            | Ed448PublicKey
            | X25519PublicKey
            | X448PublicKey
        ),
    )

    cert = (
        cert_builder.subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # For type checking, we need to ensure we're using supported key types
        # Import the exact expected types
        .sign(
            # We'll use a runtime assertion to validate that private_key is a supported type
            # Then we'll let the type checker assume it's correct
            private_key,  # type: ignore
            hash_algorithm,
        )
    )

    return cert


def create_ca() -> None:
    """Create a new CA with configuration and keys."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before creating the CA."
        )
        return

    # Check if CA already exists
    ca_cert_path = Path("certs/ca/ca.crt")
    ca_key_path = Path("certs/ca/ca.key.enc")

    if ca_cert_path.exists() or ca_key_path.exists():
        if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
            return

    # Create certificate directories
    Path("certs/ca").mkdir(parents=True, exist_ok=True)

    # Load config
    config = load_config()

    # Get password for key encryption
    password = get_password()
    if not password and config["ca"]["password"]["min_length"] > 0:
        return

    # Generate key
    key_algorithm = config["ca"]["key_algorithm"]

    console.print(f"Generating {key_algorithm} key...")
    private_key = generate_key(key_algorithm=key_algorithm)

    # Generate self-signed certificate
    validity_days = calculate_validity_days(config["ca"]["validity"])
    console.print(f"Generating self-signed CA certificate valid for {validity_days} days...")
    cert = generate_ca_cert(private_key, config, validity_days)

    # Save encrypted key and certificate
    with open(ca_key_path, "wb") as f:
        f.write(encrypt_key(private_key, password))

    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

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


def renew_ca_cert() -> None:
    """Renew the CA certificate using the existing key."""
    # Check if CA exists
    ca_cert_path = Path("certs/ca/ca.crt")
    ca_key_path = Path("certs/ca/ca.key.enc")

    if not ca_cert_path.exists() or not ca_key_path.exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        return

    # CA certificate path exists, no need to load it for backup anymore

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

    # Load config
    config = load_config()

    # Generate a new certificate with the same key
    validity_days = calculate_validity_days(config["ca"]["validity"])
    console.print(f"Renewing CA certificate with the existing key (valid for {validity_days} days)...")

    # Create a new CA certificate
    new_ca_cert = generate_ca_cert(ca_key, config, validity_days)

    # Save the new certificate
    with open(ca_cert_path, "wb") as f:
        f.write(new_ca_cert.public_bytes(encoding=Encoding.PEM))

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
    # Check if CA exists
    ca_cert_path = Path("certs/ca/ca.crt")
    ca_key_path = Path("certs/ca/ca.key.enc")

    if not ca_cert_path.exists() or not ca_key_path.exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        return

    # CA certificate path exists, no need to load it for backup anymore

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
    with open(ca_cert_path, "wb") as f:
        f.write(new_ca_cert.public_bytes(encoding=Encoding.PEM))

    with open(ca_key_path, "wb") as f:
        f.write(encrypt_key(new_ca_key, password))

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


def import_ca(cert_path: str | Path, key_path: str | Path) -> bool:
    """Import an existing CA certificate and key."""
    # Check if CA already exists
    ca_cert_dest = Path("certs/ca/ca.crt")
    ca_key_dest = Path("certs/ca/ca.key.enc")

    if ca_cert_dest.exists() or ca_key_dest.exists():
        if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
            return False

    # Check if source files exist
    src_cert_path = Path(cert_path)
    src_key_path = Path(key_path)

    if not src_cert_path.exists():
        console.print(f"[bold red]Error:[/bold red] Certificate file not found: {cert_path}")
        return False

    if not src_key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Key file not found: {key_path}")
        return False

    # Create certificate directories
    Path("certs/ca").mkdir(parents=True, exist_ok=True)

    # Load the certificate to extract information
    try:
        with open(src_cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception as e:
        console.print(f"[bold red]Error loading certificate:[/bold red] {str(e)}")
        return False

    # Load the key
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
                return False
    except Exception as e:
        console.print(f"[bold red]Error loading key:[/bold red] {str(e)}")
        return False

    # Verify that the certificate and key match
    cert_public_key = cert.public_key()
    key_public_key = private_key.public_key()

    # Verify that the public keys match
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

    console.print("✅ Verified that certificate and key match")

    # Get password for encrypting the key
    dest_password = get_password()
    if not dest_password:
        return False

    # Encrypt and save the key
    with open(ca_key_dest, "wb") as f:
        f.write(encrypt_key(private_key, dest_password))

    # Save the certificate
    with open(ca_cert_dest, "wb") as f:
        f.write(cert_data)

    console.print("✅ CA imported successfully")
    console.print(f"   Certificate: [bold]{ca_cert_dest}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{ca_key_dest}[/bold]")

    # Update inventory
    inventory = load_inventory()
    inventory["ca"] = {
        "serial": format(cert.serial_number, "x"),
        "not_after": cert.not_valid_after.isoformat(),
        "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
    }
    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def show_ca_info(json_output: bool = False) -> None:
    """Show information about the CA certificate."""
    # Check if CA exists
    ca_cert_path = Path("certs/ca/ca.crt")

    if not ca_cert_path.exists():
        console.print("[bold red]Error:[/bold red] CA certificate not found. Please initialize the CA first.")
        return

    # Load the certificate
    try:
        with open(ca_cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception as e:
        console.print(f"[bold red]Error loading certificate:[/bold red] {str(e)}")
        return

    # Extract information
    ca_info: dict[str, Any] = {
        "subject": {
            "common_name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "organization": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
            "organizational_unit": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value,
            "country": cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value,
            "state": cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value,
            "locality": cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value,
            "email": cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value,
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
        console.print(f"Subject: {ca_info['subject']['common_name']}")
        console.print(f"Organization: {ca_info['subject']['organization']}")
        console.print(f"Organizational Unit: {ca_info['subject']['organizational_unit']}")
        console.print(f"Country: {ca_info['subject']['country']}")
        console.print(f"State/Province: {ca_info['subject']['state']}")
        console.print(f"Locality: {ca_info['subject']['locality']}")
        console.print(f"Email: {ca_info['subject']['email']}")
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
