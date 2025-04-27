"""Certificate Authority operations for ReactorCA."""

import datetime
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID
from rich.console import Console

from ca.utils import (
    create_default_config,
    get_password,
    load_config,
    load_inventory,
    save_inventory,
    update_inventory,
)

console = Console()

def generate_key(algorithm="RSA", size=4096):
    """Generate a new private key with the specified algorithm and size."""
    if algorithm.upper() == "RSA":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
        )
    elif algorithm.upper() == "EC":
        # For EC, size should be a curve name like "secp256r1"
        curve_name = size
        if curve_name.lower() == "p256":
            curve = ec.SECP256R1()
        elif curve_name.lower() == "p384":
            curve = ec.SECP384R1()
        elif curve_name.lower() == "p521":
            curve = ec.SECP521R1()
        else:
            curve = ec.SECP256R1()  # Default

        return ec.generate_private_key(curve=curve)
    else:
        raise ValueError(f"Unsupported key algorithm: {algorithm}")


def encrypt_key(private_key, password):
    """Encrypt a private key with a password."""
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )


def decrypt_key(key_path, password):
    """Decrypt a private key file with a password."""
    with open(key_path, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=password.encode())


def generate_ca_cert(private_key, config, validity_days=3650):
    """Generate a self-signed CA certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, config["ca"]["common_name"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config["ca"]["organization"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config["ca"]["organization_unit"]),
        x509.NameAttribute(NameOID.COUNTRY_NAME, config["ca"]["country"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config["ca"]["state"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config["ca"]["locality"]),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, config["ca"]["email"]),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
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
        .sign(private_key, hashes.SHA256())
    )

    return cert


def initialize_ca():
    """Initialize a new CA with configuration and keys."""
    # Check if CA already exists
    ca_cert_path = Path("certs/ca/ca.crt")
    ca_key_path = Path("certs/ca/ca.key.enc")

    if ca_cert_path.exists() or ca_key_path.exists():
        if not click.confirm("CA already exists. Do you want to overwrite it?", default=False):
            return

    # Create config directories if they don't exist
    Path("config").mkdir(exist_ok=True)
    Path("certs/ca").mkdir(parents=True, exist_ok=True)

    # Create default config if it doesn't exist
    config_path = Path("config/ca_config.yaml")

    if not config_path.exists():
        create_default_config()
        console.print(f"Created default configuration at [bold]{config_path}[/bold]")
        console.print("Please review and customize it before proceeding.")
        return

    # Load config
    config = load_config()

    # Get password for key encryption
    password = get_password()
    if not password:
        return

    # Generate key
    key_algo = config["ca"]["key"]["algorithm"]
    key_size = config["ca"]["key"]["size"]

    console.print(f"Generating {key_algo} key...")
    private_key = generate_key(algorithm=key_algo, size=key_size)

    # Generate self-signed certificate
    validity_days = config["ca"]["validity_days"]
    console.print(f"Generating self-signed CA certificate valid for {validity_days} days...")
    cert = generate_ca_cert(private_key, config, validity_days)

    # Save encrypted key and certificate
    with open(ca_key_path, "wb") as f:
        f.write(encrypt_key(private_key, password))

    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

    console.print("✅ CA initialized successfully")
    console.print(f"  Certificate: [bold]{ca_cert_path}[/bold]")
    console.print(f"  Private key (encrypted): [bold]{ca_key_path}[/bold]")

    # Initialize inventory
    inventory = {
        "last_update": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ca": {
            "serial": format(cert.serial_number, "x"),
            "not_after": cert.not_valid_after.isoformat(),
            "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
        },
        "hosts": []
    }

    save_inventory(inventory)
    console.print("📋 Inventory initialized")


def import_key(key_type, hostname, key_path, cert_path=None):
    """Import an existing private key and optionally a certificate."""
    if key_type not in ["ca", "host"]:
        raise ValueError("Key type must be 'ca' or 'host'")

    if key_type == "host" and not hostname:
        raise ValueError("Hostname is required for host key import")

    # Check if source files exist
    src_key_path = Path(key_path)
    if not src_key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Key file not found: {key_path}")
        return

    if cert_path:
        src_cert_path = Path(cert_path)
        if not src_cert_path.exists():
            console.print(f"[bold red]Error:[/bold red] Certificate file not found: {cert_path}")
            return

    # Determine destination paths
    if key_type == "ca":
        dst_key_path = Path("certs/ca/ca.key.enc")
        dst_cert_path = Path("certs/ca/ca.crt") if cert_path else None
    else:  # host
        host_dir = Path(f"certs/hosts/{hostname}")
        host_dir.mkdir(parents=True, exist_ok=True)
        dst_key_path = host_dir / "cert.key.enc"
        dst_cert_path = host_dir / "cert.crt" if cert_path else None

    # Get password for key encryption
    password = get_password()
    if not password:
        return

    # Read the key, encrypt it, and save it
    try:
        with open(src_key_path, "rb") as f:
            key_data = f.read()

        # Try to load it without password first
        try:
            private_key = load_pem_private_key(key_data, password=None)
        except (TypeError, ValueError):
            # If that fails, prompt for the source key password
            src_password = click.prompt(
                "Enter source key password", hide_input=True, default="", show_default=False
            )
            if src_password:
                private_key = load_pem_private_key(key_data, password=src_password.encode())
            else:
                console.print("[bold red]Error:[/bold red] Source key is encrypted but no password provided")
                return

        # Encrypt with the new password and save
        with open(dst_key_path, "wb") as f:
            f.write(encrypt_key(private_key, password))

        console.print(f"✅ Key imported and encrypted: [bold]{dst_key_path}[/bold]")

        # Copy certificate if provided
        if cert_path and dst_cert_path:
            with open(src_cert_path, "rb") as src, open(dst_cert_path, "wb") as dst:
                dst.write(src.read())
            console.print(f"✅ Certificate imported: [bold]{dst_cert_path}[/bold]")

            # Update inventory
            if key_type == "ca":
                # Load the certificate to extract information
                with open(dst_cert_path, "rb") as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)

                inventory = load_inventory()
                inventory["ca"] = {
                    "serial": format(cert.serial_number, "x"),
                    "not_after": cert.not_valid_after.isoformat(),
                    "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                }
                inventory["last_update"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                save_inventory(inventory)
                console.print("📋 Inventory updated")

            elif hostname:
                update_inventory()
                console.print("📋 Inventory updated")

    except Exception as e:
        console.print(f"[bold red]Error importing key:[/bold red] {str(e)}")
        return
