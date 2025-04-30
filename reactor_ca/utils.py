"""Utility functions for ReactorCA."""

import datetime
import ipaddress
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import click
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.general_name import (
    DirectoryName,
    OtherName,
    RegisteredID,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID
from rich.console import Console

# Constants for expiration warnings
EXPIRY_CRITICAL = 30  # days
EXPIRY_WARNING = 90  # days

console = Console()


@dataclass
class SubjectIdentity:
    """Container for certificate subject identity information."""

    common_name: str
    organization: str = ""
    organization_unit: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""
    email: str = ""

    def to_x509_name(self: "SubjectIdentity") -> x509.Name:
        """Convert subject identity to x509.Name object.

        Returns
        -------
            x509.Name object with the subject attributes

        """
        subject_attributes = []

        # Common Name is required
        subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, self.common_name))

        # Add other attributes if provided
        if self.organization:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))
        if self.organization_unit:
            subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organization_unit))
        if self.country:
            subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.country))
        if self.state:
            subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state))
        if self.locality:
            subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality))
        if self.email:
            subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email))

        return x509.Name(subject_attributes)

    @classmethod
    def from_x509_name(cls: type["SubjectIdentity"], name: x509.Name) -> "SubjectIdentity":
        """Create a SubjectIdentity from an x509.Name object.

        Args:
        ----
            name: The x509.Name object to convert

        Returns:
        -------
            A new SubjectIdentity object

        """

        # Helper function to safely extract attributes from the name
        def get_attr_value(oid: x509.ObjectIdentifier) -> str:
            attrs = name.get_attributes_for_oid(oid)
            return str(attrs[0].value) if attrs else ""

        return cls(
            common_name=get_attr_value(NameOID.COMMON_NAME),
            organization=get_attr_value(NameOID.ORGANIZATION_NAME),
            organization_unit=get_attr_value(NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=get_attr_value(NameOID.COUNTRY_NAME),
            state=get_attr_value(NameOID.STATE_OR_PROVINCE_NAME),
            locality=get_attr_value(NameOID.LOCALITY_NAME),
            email=get_attr_value(NameOID.EMAIL_ADDRESS),
        )


# Module-level cache for password
# Using a list as a container to avoid global statement warnings when modifying
_password_cache_container: list[str | None] = [None]


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    dirs = ["config", "certs/ca", "certs/hosts"]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def calculate_validity_days(validity_config: dict[str, int]) -> int:
    """Calculate validity period in days based on the configuration."""
    if "days" in validity_config:
        return validity_config["days"]
    elif "years" in validity_config:
        return validity_config["years"] * 365
    else:
        # Default to 1 year if neither is specified
        return 365


def create_default_config() -> None:
    """Create default configuration files."""
    ca_config: dict[str, Any] = {
        "ca": {
            "common_name": "Reactor CA",
            "organization": "Reactor Homelab",
            "organization_unit": "IT",
            "country": "DE",
            "state": "Niedersachsen",
            "locality": "Hannover",
            "email": "admin@example.com",
            "key_algorithm": "RSA4096",  # Use appropriate format matching the schema
            "validity": {
                "years": 10,
            },
            "password": {
                "min_length": 12,
                # Session caching is always enabled
                "file": "",  # Path to password file
                "env_var": "REACTOR_CA_PASSWORD",  # Environment variable for password
            },
        }
    }

    hosts_config: dict[str, Any] = {
        "hosts": [
            {
                "name": "server1.example.com",
                "common_name": "server1.example.com",
                # Optional certificate metadata fields (will use CA defaults if not specified)
                # "organization": "Custom Organization",
                # "organization_unit": "Custom Department",
                # "country": "US",
                # "state": "California",
                # "locality": "San Francisco",
                # "email": "admin@custom.com",
                "alternative_names": {
                    "dns": [
                        "www.example.com",
                        "api.example.com",
                    ],
                    "ip": [
                        "192.168.1.10",
                    ],
                },
                "export": {
                    "cert": "../path/to/export/cert/server1.pem",
                    "chain": "../path/to/export/cert/server1-chain.pem",  # Optional full chain
                },
                "deploy": {
                    # Optional deployment command with variable substitution
                    "command": "cp ${cert} /etc/nginx/ssl/server1.pem "
                    + "&& cp ${private_key} /etc/nginx/ssl/server1.key && systemctl reload nginx",
                },
                "validity": {
                    "years": 1,
                },
                "key_algorithm": "RSA2048",  # Use appropriate format matching the schema
            },
        ]
    }

    # Create config directory if it doesn't exist
    Path("config").mkdir(exist_ok=True)

    # Write CA config with header comment
    ca_config_path = Path("config/ca_config.yaml")
    with open(ca_config_path, "w") as f:
        f.write("# ReactorCA Configuration\n")
        f.write("# This file contains settings for the Certificate Authority\n")
        f.write("# It is safe to modify this file directly\n\n")
        yaml.dump(ca_config, f, default_flow_style=False, sort_keys=False)

    # Write hosts config with header comment
    hosts_config_path = Path("config/hosts.yaml")
    with open(hosts_config_path, "w") as f:
        f.write("# ReactorCA Hosts Configuration\n")
        f.write("# This file contains settings for host certificates\n")
        f.write("# It is safe to modify this file directly\n\n")
        yaml.dump(hosts_config, f, default_flow_style=False, sort_keys=False)

    console.print("✅ Created default configuration files:")
    console.print(f"   CA config: [bold]{ca_config_path}[/bold]")
    console.print(f"   Hosts config: [bold]{hosts_config_path}[/bold]")
    console.print("Please review and customize these files before initializing the CA.")


def load_yaml_config(config_file: str) -> dict[str, Any]:
    """Load YAML configuration file."""
    with open(config_file) as f:
        return yaml.safe_load(f)


def load_config() -> dict[str, Any]:
    """Load CA configuration."""
    config_path = Path("config/ca_config.yaml")

    if not config_path.exists():
        console.print(f"[bold red]Error:[/bold red] Configuration file not found: {config_path}")
        console.print("Run 'ca config init' to create a default configuration.")
        sys.exit(1)  # This exits the program

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            console.print("[bold red]Error:[/bold red] Invalid configuration format")
            sys.exit(1)  # This exits the program

        return config
    except Exception as e:
        console.print(f"[bold red]Error loading configuration:[/bold red] {str(e)}")
        sys.exit(1)  # This exits the program

    # For type checker only - this is never reached
    # mypy doesn't understand that sys.exit prevents execution from continuing
    raise AssertionError("Unreachable code")


def load_hosts_config() -> dict[str, Any]:
    """Load hosts configuration."""
    hosts_path = Path("config/hosts.yaml")

    if not hosts_path.exists():
        console.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {hosts_path}")
        return {"hosts": []}

    try:
        with open(hosts_path) as f:
            hosts_config = yaml.safe_load(f)

        if not isinstance(hosts_config, dict):
            console.print("[bold red]Error:[/bold red] Invalid hosts configuration format")
            return {"hosts": []}

        return hosts_config
    except Exception as e:
        console.print(f"[bold red]Error loading hosts configuration:[/bold red] {str(e)}")
        return {"hosts": []}  # Return empty hosts list as fallback


def read_password_from_file(password_file: str) -> str | None:
    """Read password from a file."""
    try:
        with open(password_file) as f:
            return f.read().strip()
    except Exception as e:
        console.print(f"[bold red]Error reading password file:[/bold red] {str(e)}")
        return None


def get_password() -> str | None:
    """Get password for key encryption/decryption, with multiple sources."""
    # Load config to check password settings
    config = load_config()
    min_length = config["ca"]["password"]["min_length"]
    password_file = config["ca"]["password"].get("file", "")
    env_var = config["ca"]["password"].get("env_var", "")

    # If password is already cached, return it
    if _password_cache_container[0]:
        return _password_cache_container[0]

    # Try to get the password from a file
    if password_file:
        password = read_password_from_file(password_file)
        if password and len(password) >= min_length:
            _password_cache_container[0] = password
            return password

    # Try to get the password from an environment variable
    if env_var and env_var in os.environ:
        password = os.environ[env_var]
        if password and len(password) >= min_length:
            _password_cache_container[0] = password
            return password

    # If we still don't have a password, prompt the user
    password = click.prompt(
        "Enter CA master password",
        hide_input=True,
        confirmation_prompt=False,
    )

    # Validate password length
    if password and len(password) < min_length:
        console.print(f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long")
        return None

    # Cache password for session
    _password_cache_container[0] = password

    return password


def save_inventory(inventory: dict[str, Any]) -> None:
    """Save certificate inventory."""
    inventory_path = Path("inventory.yaml")

    try:
        with open(inventory_path, "w") as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        console.print(f"[bold red]Error saving inventory:[/bold red] {str(e)}")


def load_inventory() -> dict[str, Any]:
    """Load certificate inventory."""
    inventory_path = Path("inventory.yaml")

    if not inventory_path.exists():
        # Create empty inventory
        inventory = {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {},
            "hosts": [],
        }
        save_inventory(inventory)
        return inventory

    try:
        with open(inventory_path) as f:
            inventory = yaml.safe_load(f)

        return inventory
    except Exception as e:
        console.print(f"[bold red]Error loading inventory:[/bold red] {str(e)}")
        # Return empty inventory as fallback
        return {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {},
            "hosts": [],
        }


def scan_cert_files() -> dict[str, Any]:
    """Scan certificate files and update inventory."""
    inventory = load_inventory()
    ca_dir = Path("certs/ca")
    hosts_dir = Path("certs/hosts")

    # Check CA certificate
    ca_cert_path = ca_dir / "ca.crt"
    if ca_cert_path.exists():
        try:
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            inventory["ca"] = {
                "serial": format(ca_cert.serial_number, "x"),
                "not_after": ca_cert.not_valid_after.isoformat(),
                "fingerprint": "SHA256:" + ca_cert.fingerprint(hashes.SHA256()).hex(),
            }
        except Exception as e:
            console.print(f"[bold red]Error loading CA certificate:[/bold red] {str(e)}")

    # Check host certificates
    if hosts_dir.exists():
        host_dirs = [d for d in hosts_dir.iterdir() if d.is_dir()]

        for host_dir in host_dirs:
            hostname = host_dir.name
            cert_path = host_dir / "cert.crt"

            if cert_path.exists():
                try:
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())

                    # Find existing host entry or create new one
                    for host in inventory.setdefault("hosts", []):
                        if host["name"] == hostname:
                            host["serial"] = format(cert.serial_number, "x")
                            host["not_after"] = cert.not_valid_after.isoformat()
                            host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
                            # Keep renewal count if exists
                            break
                    else:
                        # Add new entry if not found
                        inventory.setdefault("hosts", []).append(
                            {
                                "name": hostname,
                                "serial": format(cert.serial_number, "x"),
                                "not_after": cert.not_valid_after.isoformat(),
                                "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                                "renewal_count": 0,
                            }
                        )
                except Exception as e:
                    console.print(f"[bold red]Error loading certificate for {hostname}:[/bold red] {str(e)}")

    # Update last_update timestamp
    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()

    # Save updated inventory
    save_inventory(inventory)

    return inventory


def update_inventory() -> dict[str, Any]:
    """Update inventory based on certificate files."""
    return scan_cert_files()


def change_password() -> None:
    """Change password for all encrypted keys."""
    # Get old password
    old_password = click.prompt(
        "Enter current password",
        hide_input=True,
        confirmation_prompt=False,
    )

    # Get new password with confirmation
    new_password = click.prompt(
        "Enter new password",
        hide_input=True,
        confirmation_prompt=True,
    )

    # Load config to check password requirements
    config = load_config()
    min_length = config["ca"]["password"]["min_length"]

    # Validate new password length
    if len(new_password) < min_length:
        console.print(f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long")
        return

    # Find all encrypted key files
    key_files = []

    # CA key
    ca_key_path = Path("certs/ca/ca.key.enc")
    if ca_key_path.exists():
        key_files.append(ca_key_path)

    # Host keys
    hosts_dir = Path("certs/hosts")
    if hosts_dir.exists():
        for host_dir in [d for d in hosts_dir.iterdir() if d.is_dir()]:
            key_path = host_dir / "cert.key.enc"
            if key_path.exists():
                key_files.append(key_path)

    if not key_files:
        console.print("[bold yellow]Warning:[/bold yellow] No encrypted key files found")
        return

    # Process each key file
    success_count = 0
    error_count = 0

    for key_path in key_files:
        try:
            # Read encrypted key
            with open(key_path, "rb") as f:
                encrypted_key_data = f.read()

            # Decrypt with old password
            try:
                private_key = load_pem_private_key(
                    encrypted_key_data,
                    password=old_password.encode(),
                )
            except Exception as e:
                console.print(f"[bold red]Error decrypting {key_path}:[/bold red] {str(e)}")
                error_count += 1
                continue

            # Re-encrypt with new password
            new_encrypted_data = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(new_password.encode()),
            )

            # Write updated key
            with open(key_path, "wb") as f:
                f.write(new_encrypted_data)

            success_count += 1
            console.print(f"✅ Re-encrypted {key_path}")

        except Exception as e:
            console.print(f"[bold red]Error processing {key_path}:[/bold red] {str(e)}")
            error_count += 1

    # Update password cache for session
    _password_cache_container[0] = new_password

    # Summary
    console.print(f"\n✅ Changed password for {success_count} key files")
    if error_count > 0:
        console.print(f"❌ Failed to change password for {error_count} key files")


# File and Path Operations
def ensure_directory_exists(directory_path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
    ----
        directory_path: Path to directory

    Returns:
    -------
        Path object of the directory

    """
    path = Path(directory_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def path_exists(path: str | Path) -> bool:
    """Check if a path exists.

    Args:
    ----
        path: Path to check

    Returns:
    -------
        True if path exists, False otherwise

    """
    return Path(path).exists()


# Certificate and Key File Operations
def load_certificate(cert_path: str | Path) -> x509.Certificate:
    """Load an X.509 certificate from a file.

    Args:
    ----
        cert_path: Path to certificate file

    Returns:
    -------
        X.509 certificate object

    """
    path = Path(cert_path)
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")

    with open(path, "rb") as f:
        cert_data = f.read()

    return x509.load_pem_x509_certificate(cert_data)


def save_certificate(cert: x509.Certificate, cert_path: str | Path) -> None:
    """Save an X.509 certificate to a file in PEM format.

    Args:
    ----
        cert: X.509 certificate object
        cert_path: Path to save certificate to

    """
    path = Path(cert_path)
    ensure_directory_exists(path.parent)

    with open(path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))


def load_private_key(key_path: str | Path, password: bytes | None = None) -> PrivateKeyTypes:
    """Load an RSA private key from a file.

    Args:
    ----
        key_path: Path to private key file
        password: Optional password if key is encrypted

    Returns:
    -------
        Private key object

    """
    path = Path(key_path)
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {key_path}")

    with open(path, "rb") as f:
        key_data = f.read()

    return load_pem_private_key(key_data, password=password)


def save_private_key(key: PrivateKeyTypes, key_path: str | Path, password: bytes | None = None) -> None:
    """Save a private key to a file in PEM format.

    Args:
    ----
        key: Private key object
        key_path: Path to save key to
        password: Optional password to encrypt the key

    """
    path = Path(key_path)
    ensure_directory_exists(path.parent)

    encryption_algorithm: NoEncryption | BestAvailableEncryption = NoEncryption()
    if password:
        encryption_algorithm = BestAvailableEncryption(password)

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption_algorithm
            )
        )


def load_crl(crl_path: str | Path) -> x509.CertificateRevocationList:
    """Load a Certificate Revocation List from a file.

    Args:
    ----
        crl_path: Path to CRL file

    Returns:
    -------
        CertificateRevocationList object

    """
    path = Path(crl_path)
    if not path.exists():
        raise FileNotFoundError(f"CRL file not found: {crl_path}")

    with open(path, "rb") as f:
        crl_data = f.read()

    return x509.load_pem_x509_crl(crl_data)


def save_crl(crl: x509.CertificateRevocationList, crl_path: str | Path) -> None:
    """Save a Certificate Revocation List to a file in PEM format.

    Args:
    ----
        crl: CertificateRevocationList object
        crl_path: Path to save CRL to

    """
    path = Path(crl_path)
    ensure_directory_exists(path.parent)

    with open(path, "wb") as f:
        f.write(crl.public_bytes(Encoding.PEM))


# Certificate Metadata Handling
def get_certificate_metadata(cert: x509.Certificate) -> SubjectIdentity:
    """Extract common metadata fields from a certificate.

    Args:
    ----
        cert: The certificate to extract metadata from

    Returns:
    -------
        SubjectIdentity with common certificate metadata fields

    """
    return SubjectIdentity.from_x509_name(cert.subject)


def format_certificate_expiry(days_remaining: int) -> str:
    """Format days remaining until certificate expiry with appropriate color coding.

    Args:
    ----
        days_remaining: Number of days until certificate expires

    Returns:
    -------
        Rich-formatted string with appropriate color coding

    """
    if days_remaining < 0:
        return f"[bold red]{days_remaining} (expired)[/bold red]"
    elif days_remaining < EXPIRY_CRITICAL:
        return f"[bold orange]{days_remaining}[/bold orange]"
    elif days_remaining < EXPIRY_WARNING:
        return f"[bold yellow]{days_remaining}[/bold yellow]"
    else:
        return f"{days_remaining}"


def get_host_paths(hostname: str) -> tuple[Path, Path, Path]:
    """Get standard paths for a host's certificates and keys.

    Args:
    ----
        hostname: The hostname to get paths for

    Returns:
    -------
        Tuple containing (host_dir, cert_path, key_path)

    """
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_path = host_dir / "cert.key.enc"
    return host_dir, cert_path, key_path


def create_subject_name(subject_identity: SubjectIdentity) -> x509.Name:
    """Create a certificate subject name from a SubjectIdentity.

    Args:
    ----
        subject_identity: Subject identity information

    Returns:
    -------
        x509.Name object with the provided attributes

    """
    return subject_identity.to_x509_name()


def create_subject_from_config(
    hostname: str, config: dict[str, Any], host_config: dict[str, Any] | None = None
) -> x509.Name:
    """Create a certificate subject from CA config and optional host config.

    Args:
    ----
        hostname: The hostname to use as common name
        config: The CA configuration containing default values
        host_config: Optional host configuration that can override CA defaults

    Returns:
    -------
        x509.Name object with the configured attributes

    """
    # Create a SubjectIdentity with fields from host_config (if available) or from CA config
    subject = SubjectIdentity(
        common_name=hostname,
        organization=host_config.get("organization", config["ca"]["organization"])
        if host_config
        else config["ca"]["organization"],
        organization_unit=host_config.get("organization_unit", config["ca"]["organization_unit"])
        if host_config
        else config["ca"]["organization_unit"],
        country=host_config.get("country", config["ca"]["country"]) if host_config else config["ca"]["country"],
        state=host_config.get("state", config["ca"]["state"]) if host_config else config["ca"]["state"],
        locality=host_config.get("locality", config["ca"]["locality"]) if host_config else config["ca"]["locality"],
        email=host_config.get("email", config["ca"]["email"]) if host_config else config["ca"]["email"],
    )

    return subject.to_x509_name()


def create_certificate_builder(
    subject: x509.Name, issuer: x509.Name, public_key: PublicKeyTypes, validity_days: int = 365
) -> x509.CertificateBuilder:
    """Create a certificate builder with the essential attributes.

    Args:
    ----
        subject: The certificate subject
        issuer: The certificate issuer (CA)
        public_key: Public key to include in the certificate
        validity_days: Validity period in days

    Returns:
    -------
        Initialized certificate builder

    """
    now = datetime.datetime.now(datetime.UTC)

    # DHPublicKey is not supported by certificate builder, so we need to check for it
    from cryptography.hazmat.primitives.asymmetric import dh

    if isinstance(public_key, dh.DHPublicKey):
        raise ValueError("DHPublicKey is not supported for certificates")

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )


def add_standard_extensions(
    cert_builder: x509.CertificateBuilder, is_ca: bool = False, san_list: list[Any] | None = None
) -> x509.CertificateBuilder:
    """Add standard X.509 extensions to a certificate builder.

    Args:
    ----
        cert_builder: The certificate builder to add extensions to
        is_ca: Whether this is a CA certificate
        san_list: Optional list of Subject Alternative Names

    Returns:
    -------
        Certificate builder with extensions added

    """
    # Add BasicConstraints
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True,
    )

    # Add KeyUsage - different for CA vs server/client certs
    if is_ca:
        cert_builder = cert_builder.add_extension(
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
    else:
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # For non-CA certs, add ExtendedKeyUsage
    if not is_ca:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )

    # Add Subject Alternative Names if provided
    if san_list and len(san_list) > 0:
        from cryptography.x509 import GeneralName

        # Cast to the type that SubjectAlternativeName expects
        general_names = cast(list[GeneralName], san_list)

        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )

    return cert_builder


def sign_certificate(
    cert_builder: x509.CertificateBuilder, private_key: PrivateKeyTypes, hash_algo: hashes.HashAlgorithm
) -> x509.Certificate:
    """Sign a certificate builder with the given private key and hash algorithm.

    Args:
    ----
        cert_builder: The populated certificate builder
        private_key: The private key to sign with
        hash_algo: The hash algorithm to use for signing

    Returns:
    -------
        Signed certificate

    """
    # Validate the hash algorithm is one of the supported types
    valid_hash_types = (
        hashes.SHA224,
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
        hashes.SHA3_224,
        hashes.SHA3_256,
        hashes.SHA3_384,
        hashes.SHA3_512,
    )
    assert isinstance(hash_algo, valid_hash_types), "Unsupported hash algorithm"

    # Sign the certificate
    # We need to specifically exclude DHPrivateKey and X25519/X448PrivateKey from the sign method
    # because the cryptography library doesn't support signing with these keys
    from cryptography.hazmat.primitives.asymmetric import dh, x448, x25519

    if isinstance(private_key, dh.DHPrivateKey | x25519.X25519PrivateKey | x448.X448PrivateKey):
        raise ValueError(f"Cannot sign with {type(private_key).__name__} as it is not supported for signing")
    return cert_builder.sign(private_key, hash_algo)


# Subject Alternative Name (SAN) processing
def process_dns_names(names: list[str]) -> list[x509.DNSName]:
    """Process DNS names into appropriate SAN format.

    Args:
    ----
        names: List of DNS name strings

    Returns:
    -------
        List of x509.DNSName objects

    """
    return [x509.DNSName(name) for name in names]


def process_ip_addresses(ips: list[str]) -> list[x509.IPAddress]:
    """Process IP addresses into appropriate SAN format.

    Args:
    ----
        ips: List of IP address strings

    Returns:
    -------
        List of valid x509.IPAddress objects

    """
    result = []

    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            result.append(x509.IPAddress(ip_obj))
        except ValueError:
            console.print(f"[yellow]Warning:[/yellow] Invalid IP address {ip}, skipping")

    return result


def process_email_addresses(emails: list[str]) -> list[x509.RFC822Name]:
    """Process email addresses into appropriate SAN format.

    Args:
    ----
        emails: List of email address strings

    Returns:
    -------
        List of valid x509.RFC822Name objects

    """
    result = []

    for email in emails:
        # Simple email validation
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            result.append(x509.RFC822Name(email))
        else:
            console.print(f"[yellow]Warning:[/yellow] Invalid email address {email}, skipping")

    return result


def process_uri_addresses(uris: list[str]) -> list[x509.UniformResourceIdentifier]:
    """Process URIs into appropriate SAN format.

    Args:
    ----
        uris: List of URI strings

    Returns:
    -------
        List of valid x509.UniformResourceIdentifier objects

    """
    result = []

    for uri in uris:
        try:
            # Validate URI
            parsed = urlparse(uri)
            if parsed.scheme and parsed.netloc:
                result.append(UniformResourceIdentifier(uri))
            else:
                raise ValueError("Invalid URI format")
        except Exception:
            console.print(f"[yellow]Warning:[/yellow] Invalid URI {uri}, skipping")

    return result


def process_directory_names(dns: list[str]) -> list[x509.DirectoryName]:
    """Process directory names into appropriate SAN format.

    Args:
    ----
        dns: List of directory name strings (format "CN=example,O=org,C=US")

    Returns:
    -------
        List of valid x509.DirectoryName objects

    """
    result = []

    for dn in dns:
        try:
            # Expect format like "CN=example,O=org,C=US"
            attrs = []
            for part in dn.split(","):
                if "=" in part:
                    attr_type, value = part.strip().split("=", 1)
                    attr_type = attr_type.upper()

                    if attr_type == "CN":
                        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
                    elif attr_type == "O":
                        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
                    elif attr_type == "OU":
                        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
                    elif attr_type == "C":
                        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
                    elif attr_type == "ST":
                        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
                    elif attr_type == "L":
                        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
                    elif attr_type == "E":
                        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, value))

            if attrs:
                # Convert x509.Name to the correct type for DirectoryName
                name = x509.Name(attrs)
                # Using proper typing for DirectoryName that accepts x509.Name
                result.append(DirectoryName(name))
            else:
                raise ValueError("No valid attributes found")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid directory name {dn}: {str(e)}, skipping")

    return result


def process_registered_ids(oids: list[str]) -> list[x509.RegisteredID]:
    """Process OID strings into appropriate SAN format.

    Args:
    ----
        oids: List of OID strings

    Returns:
    -------
        List of valid x509.RegisteredID objects

    """
    from cryptography.x509 import ObjectIdentifier

    result = []

    for oid in oids:
        try:
            # Validate OID format
            if re.match(r"^\d+(\.\d+)*$", oid):
                result.append(RegisteredID(ObjectIdentifier(oid)))
            else:
                raise ValueError("Invalid OID format")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid OID {oid}: {str(e)}, skipping")

    return result


def process_other_names(other_names: list[str]) -> list[x509.OtherName]:
    """Process other name strings into appropriate SAN format.

    Args:
    ----
        other_names: List of other name strings (format "oid:value")

    Returns:
    -------
        List of valid x509.OtherName objects

    """
    from cryptography.x509 import ObjectIdentifier

    result = []

    for other_name in other_names:
        try:
            # Format expected: "oid:value"
            if ":" in other_name:
                oid_str, value = other_name.split(":", 1)
                oid_str = oid_str.strip()
                value = value.strip()

                # Validate OID format
                if re.match(r"^\d+(\.\d+)*$", oid_str):
                    oid_obj = ObjectIdentifier(oid_str)
                    # Encode value as bytes
                    value_bytes = value.encode("utf-8")
                    result.append(OtherName(oid_obj, value_bytes))
                else:
                    raise ValueError("Invalid OID format")
            else:
                raise ValueError("Invalid format, expected 'oid:value'")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Invalid other name {other_name}: {str(e)}, skipping")

    return result


def process_all_sans(alt_names: dict[str, list[str]]) -> list[Any]:
    """Process all Subject Alternative Name types from a dictionary.

    Args:
    ----
        alt_names: Dictionary with keys for different SAN types
                  (dns, ip, email, uri, directory_name, registered_id, other_name)

    Returns:
    -------
        List of all valid SAN objects

    """
    from cryptography.x509 import GeneralName

    # Initialize the result list
    result: list[GeneralName] = []

    # Add DNS names
    if "dns" in alt_names and alt_names["dns"]:
        dns_names = process_dns_names(alt_names["dns"])
        # All items in dns_names are GeneralName subtypes which can be safely added
        result.extend(cast(list[GeneralName], dns_names))

    # Add IP addresses
    if "ip" in alt_names and alt_names["ip"]:
        ip_addresses = process_ip_addresses(alt_names["ip"])
        result.extend(cast(list[GeneralName], ip_addresses))

    # Add email addresses
    if "email" in alt_names and alt_names["email"]:
        email_addresses = process_email_addresses(alt_names["email"])
        result.extend(cast(list[GeneralName], email_addresses))

    # Add URIs
    if "uri" in alt_names and alt_names["uri"]:
        uris = process_uri_addresses(alt_names["uri"])
        result.extend(cast(list[GeneralName], uris))

    # Add directory names
    if "directory_name" in alt_names and alt_names["directory_name"]:
        directory_names = process_directory_names(alt_names["directory_name"])
        result.extend(cast(list[GeneralName], directory_names))

    # Add registered IDs (OIDs)
    if "registered_id" in alt_names and alt_names["registered_id"]:
        registered_ids = process_registered_ids(alt_names["registered_id"])
        result.extend(cast(list[GeneralName], registered_ids))

    # Add other names
    if "other_name" in alt_names and alt_names["other_name"]:
        other_names = process_other_names(alt_names["other_name"])
        result.extend(cast(list[GeneralName], other_names))

    return result


# Certificate Validation
def is_cert_valid(cert: x509.Certificate) -> bool:
    """Check if a certificate is currently valid (not expired or not yet valid).

    Args:
    ----
        cert: X.509 certificate object

    Returns:
    -------
        True if certificate is valid, False otherwise

    """
    now = datetime.datetime.now(datetime.UTC)
    return cert.not_valid_before <= now <= cert.not_valid_after


def get_certificate_fingerprint(cert: x509.Certificate, hash_algorithm: hashes.HashAlgorithm | None = None) -> str:
    """Get the fingerprint of a certificate using the specified hash algorithm.

    Args:
    ----
        cert: X.509 certificate object
        hash_algorithm: Hash algorithm to use

    Returns:
    -------
        Hex string representation of the fingerprint

    """
    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()
    fingerprint = cert.fingerprint(hash_algorithm)
    return fingerprint.hex()


def is_cert_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
    """Check if a certificate has been revoked according to a CRL.

    Args:
    ----
        cert: X.509 certificate object
        crl: CertificateRevocationList object

    Returns:
    -------
        True if certificate is revoked, False otherwise

    """
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            return True
    return False


def update_inventory_for_cert(
    inventory: dict[str, Any],
    hostname: str,
    cert: x509.Certificate,
    rekeyed: bool = False,
    renewal_count_increment: int = 1,
) -> dict[str, Any]:
    """Update certificate inventory with new certificate information.

    Args:
    ----
        inventory: The current inventory dictionary
        hostname: The hostname for this certificate
        cert: The certificate to add to inventory
        rekeyed: Whether this certificate was generated with a new key
        renewal_count_increment: Amount to increment the renewal count

    Returns:
    -------
        Updated inventory dictionary

    """
    # Find existing host entry or create new one
    for host in inventory.setdefault("hosts", []):
        if host["name"] == hostname:
            host["serial"] = format(cert.serial_number, "x")
            host["not_after"] = cert.not_valid_after.isoformat()
            host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
            host["renewal_count"] = host.get("renewal_count", 0) + renewal_count_increment
            if rekeyed:
                host["rekeyed"] = True
            break
    else:
        # Add new entry if not found
        inventory.setdefault("hosts", []).append(
            {
                "name": hostname,
                "serial": format(cert.serial_number, "x"),
                "not_after": cert.not_valid_after.isoformat(),
                "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                "renewal_count": 1,
                "rekeyed": rekeyed,
            }
        )

    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()
    return inventory


def get_host_config_by_name(hostname: str) -> dict[str, Any] | None:
    """Get host configuration for a specific hostname.

    Args:
    ----
        hostname: The hostname to look for in configuration

    Returns:
    -------
        Host configuration dictionary if found, None otherwise

    """
    hosts_config = load_hosts_config()

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            return host

    return None


def write_private_key_to_temp_file(private_key: PrivateKeyTypes, hostname: str) -> tuple[str, list[str]]:
    """Write a private key to a temporary file with secure permissions.

    Args:
    ----
        private_key: The private key to write
        hostname: Hostname for prefix

    Returns:
    -------
        Tuple of (temp file path, list of all temp files created)

    """
    temp_files = []

    # Create a temporary file for the private key with restricted permissions
    fd, temp_key_path = tempfile.mkstemp(suffix=".key", prefix=f"{hostname}-")
    temp_files.append(temp_key_path)

    # Close the file descriptor
    os.close(fd)

    # Set secure permissions (600 - owner read/write only)
    os.chmod(temp_key_path, stat.S_IRUSR | stat.S_IWUSR)

    # Write the decrypted key to the temporary file
    with open(temp_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )

    return temp_key_path, temp_files


def run_deploy_command(hostname: str, command: str) -> bool:
    """Run a deployment command for a host.

    Args:
    ----
        hostname: The hostname for the certificate
        command: The command to run with variable substitution

    Returns:
    -------
        True if deployment was successful, False otherwise

    Supports variable substitution:
    - ${cert} - Path to the host certificate file
    - ${private_key} - Path to a temporary file containing the decrypted private key

    """
    if not command:
        return False

    try:
        temp_files = []
        modified_command = command

        # Get standard paths for this host
        host_dir, cert_path, key_path = get_host_paths(hostname)

        # Replace ${cert} with certificate path if it exists
        if "${cert}" in command and cert_path.exists():
            modified_command = modified_command.replace("${cert}", str(cert_path.absolute()))

        # Handle ${private_key} if it exists in the command
        if "${private_key}" in command and key_path.exists():
            # Get password and decrypt the key
            password = get_password()
            if not password:
                console.print("[bold red]Error:[/bold red] Cannot decrypt private key - no password provided")
                return False

            try:
                from reactor_ca.ca_operations import decrypt_key

                private_key = decrypt_key(key_path, password)

                # Write key to temporary file
                temp_key_path, created_temp_files = write_private_key_to_temp_file(private_key, hostname)
                temp_files.extend(created_temp_files)

                # Replace the variable in the command
                modified_command = modified_command.replace("${private_key}", temp_key_path)

            except Exception as e:
                console.print(f"[bold red]Error preparing private key for {hostname}:[/bold red] {str(e)}")
                # Clean up any temporary files created so far
                for temp_file in temp_files:
                    try:
                        os.unlink(temp_file)
                    except Exception as ie:
                        console.print(f"[bold red]Error removing temp file:[/bold red] {str(ie)}")
                return False

        # Run the modified command
        console.print(f"Running deployment command for [bold]{hostname}[/bold]: {modified_command}")
        result = os.system(modified_command)

        # Clean up any temporary files
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except Exception as e:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Could not delete temporary file {temp_file}: {str(e)}"
                )

        if result == 0:
            console.print(f"✅ Deployment for [bold]{hostname}[/bold] completed successfully")
            return True
        else:
            console.print(f"[bold red]Deployment for {hostname} failed with exit code {result}[/bold red]")
            return False
    except Exception as e:
        console.print(f"[bold red]Error during deployment for {hostname}:[/bold red] {str(e)}")
        return False
