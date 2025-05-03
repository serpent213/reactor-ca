"""Certificate operations for ReactorCA."""

import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.general_name import DirectoryName, OtherName, RegisteredID, UniformResourceIdentifier
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.table import Table

from reactor_ca.ca_operations import (
    DEFAULT_HASH_ALGORITHM,
    generate_key,
    get_hash_algorithm,
    verify_key_algorithm,
)
from reactor_ca.config import (
    Config,
    get_host_config,
    load_ca_config,
    load_config,
    validate_config_before_operation,
)
from reactor_ca.crypto import (
    add_standard_extensions,
    create_certificate_builder,
    process_all_sans,
    sign_certificate,
)
from reactor_ca.models import (
    AlternativeNames,
    CertificateParams,
    HostConfig,
    SubjectIdentity,
)
from reactor_ca.store import Store, get_store
from reactor_ca.utils import (
    format_certificate_expiry,
    get_host_paths,
    run_deploy_command,
)

console = Console()


def load_ca_key_cert() -> tuple[PrivateKeyTypes, x509.Certificate]:
    """Load the CA key and certificate."""
    # Initialize store
    store = get_store()

    # Check if CA exists
    if not store.ca_cert_exists() or not store.ca_key_exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        raise FileNotFoundError("CA certificate or key not found")

    # Unlock the store
    if not store.unlock():
        raise ValueError("Could not unlock the store")

    # Load CA certificate and key
    ca_cert = store.load_ca_cert()
    ca_key = store.load_ca_key()

    if not ca_cert or not ca_key:
        raise FileNotFoundError("CA certificate or key not found")

    return ca_key, ca_cert


def create_certificate_with_params(
    params: CertificateParams, config: Union["Config", None] = None
) -> x509.Certificate:
    """Create a certificate using parameters object."""
    if config is None:
        config = Config.create()

    ca_config = load_ca_config(config.ca_config_path)

    # Get hash algorithm from params, host_config, or fallback to CA config
    hash_algorithm = params.hash_algorithm
    if hash_algorithm is None and params.host_config and params.host_config.hash_algorithm:
        hash_algorithm = params.host_config.hash_algorithm
    if hash_algorithm is None:
        hash_algorithm = ca_config.hash_algorithm

    hash_algo = get_hash_algorithm(hash_algorithm)

    # Create subject using host params data, using host_config when available
    host_config = params.host_config

    # Use host_config fields when available, falling back to CA config
    organization = host_config.organization if host_config and host_config.organization else ca_config.organization
    organization_unit = (
        host_config.organization_unit
        if host_config and host_config.organization_unit
        else ca_config.organization_unit
    )
    country = host_config.country if host_config and host_config.country else ca_config.country
    state = host_config.state if host_config and host_config.state else ca_config.state
    locality = host_config.locality if host_config and host_config.locality else ca_config.locality
    email = host_config.email if host_config and host_config.email else ca_config.email

    # Create subject identity
    subject_identity = SubjectIdentity(
        common_name=params.hostname,
        organization=organization,
        organization_unit=organization_unit,
        country=country,
        state=state,
        locality=locality,
        email=email,
    )
    subject = subject_identity.to_x509_name()

    # Create certificate builder
    cert_builder = create_certificate_builder(
        subject=subject,
        issuer=params.ca_cert.subject,
        public_key=params.private_key.public_key(),
        validity_days=params.validity_days,
    )

    # Process Subject Alternative Names if provided
    san_list = []
    if params.alt_names:
        san_list = process_all_sans(params.alt_names)

    # Add standard extensions to certificate
    cert_builder = add_standard_extensions(cert_builder=cert_builder, is_ca=False, san_list=san_list)

    # Sign the certificate
    cert = sign_certificate(cert_builder, params.ca_key, hash_algo)

    return cert


def create_certificate(  # noqa: PLR0913
    hostname: str,
    private_key: PrivateKeyTypes,
    ca_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    validity_days: int = 365,
    alt_names: AlternativeNames | None = None,
    hash_algorithm: str | None = None,
    host_config: HostConfig | None = None,
) -> x509.Certificate:
    """Create a certificate signed by the CA.

    Args:
    ----
        hostname: Hostname for the certificate
        private_key: Private key for the certificate
        ca_key: CA private key
        ca_cert: CA certificate
        validity_days: Number of days the certificate is valid for
        alt_names: Alternative names for the certificate
        hash_algorithm: Hash algorithm to use for signing
        host_config: Host configuration parameters

    Returns:
    -------
        Generated certificate

    """
    # Use CertificateParams to package all parameters
    params = CertificateParams(
        hostname=hostname,
        private_key=private_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=hash_algorithm,
        host_config=host_config,
    )

    return create_certificate_with_params(params)


def export_certificate(
    store: "Store",
    hostname: str,
    certificate: x509.Certificate,
    key: PrivateKeyTypes | None = None,
    chain: bool = True,
    no_export: bool = False,
) -> bool:
    """Export a certificate and optionally its private key and chain to the configured location."""
    # Store is now required and first parameter

    if no_export:
        console.print(f"Certificate export skipped for [bold]{hostname}[/bold] (--no-export flag)")
        return True  # Return True to allow deployment to proceed

    hosts_config = store.load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold yellow]Warning:[/bold yellow] Host {hostname} not found in hosts configuration")
        return False

    # Check if export configuration exists
    if "export" not in host_config:
        # Silently skip export without any warning message
        return True  # Return True to allow deployment to proceed

    export_config = host_config["export"]
    cert_path = export_config.get("cert")
    chain_path = export_config.get("chain")

    # Skip export if no export paths are configured
    if not cert_path and not chain_path:
        # Silently skip export without any warning message
        return True  # Return True to allow deployment to proceed

    export_success = False

    # Export certificate if path is configured
    if cert_path:
        cert_export_path = Path(cert_path)
        cert_export_path.parent.mkdir(parents=True, exist_ok=True)

        # Export certificate
        try:
            with open(cert_export_path, "wb") as f:
                f.write(certificate.public_bytes(encoding=Encoding.PEM))
            console.print(f"✅ Certificate exported to [bold]{cert_export_path}[/bold]")
            export_success = True
        except Exception as e:
            console.print(f"[bold red]Error exporting certificate:[/bold red] {str(e)}")

    # Export chain certificate if configured
    if chain and chain_path:
        chain_export_path = Path(chain_path)
        chain_export_path.parent.mkdir(parents=True, exist_ok=True)

        # Load CA certificate
        try:
            ca_cert = store.load_ca_cert()
            if ca_cert is None:
                raise FileNotFoundError("CA certificate not found")

            ca_cert_data = ca_cert.public_bytes(encoding=Encoding.PEM)

            # Write chain certificate (host cert + CA cert)
            with open(chain_export_path, "wb") as f:
                # Write host certificate first
                f.write(certificate.public_bytes(encoding=Encoding.PEM))
                # Then write CA certificate
                f.write(ca_cert_data)

            console.print(f"✅ Certificate chain exported to [bold]{chain_export_path}[/bold]")
            export_success = True
        except Exception as e:
            console.print(f"[bold red]Error exporting certificate chain:[/bold red] {str(e)}")

    # Return True if either no paths were configured or at least one export succeeded
    return export_success or not (cert_path or chain_path)


def deploy_host(store: "Store", hostname: str) -> bool:
    """Run the deployment script for a host."""
    # Store is now required and first parameter

    hosts_config = store.load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold yellow]Warning:[/bold yellow] Host {hostname} not found in hosts configuration")
        return False

    # Check if deployment is configured
    if "deploy" not in host_config or "command" not in host_config["deploy"]:
        console.print(f"[bold yellow]Warning:[/bold yellow] No deployment command configured for {hostname}")
        return False

    deploy_command = host_config["deploy"]["command"]
    return run_deploy_command(store, hostname, deploy_command)


def extract_hostname_from_csr(csr: x509.CertificateSigningRequest) -> str | None:
    """Extract the hostname (common name) from a CSR.

    Args:
    ----
        csr: Certificate signing request

    Returns:
    -------
        Hostname string if found, None otherwise

    """
    for attr in csr.subject:
        if attr.oid == NameOID.COMMON_NAME:
            # Handle both string and bytes value types
            return attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
    return None


def extract_sans_from_csr(csr: x509.CertificateSigningRequest) -> AlternativeNames:
    """Extract Subject Alternative Names from a CSR.

    Args:
    ----
        csr: Certificate signing request

    Returns:
    -------
        AlternativeNames object containing the SAN values

    """
    alt_names = AlternativeNames()

    for ext in csr.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for san in ext.value:
                if isinstance(san, x509.DNSName):
                    alt_names.dns.append(san.value)
                elif isinstance(san, x509.IPAddress):
                    alt_names.ip.append(str(san.value))
                elif isinstance(san, x509.RFC822Name):
                    alt_names.email.append(san.value)
                elif isinstance(san, UniformResourceIdentifier):
                    alt_names.uri.append(san.value)
                elif isinstance(san, DirectoryName):
                    alt_names.directory_name.append(format_directory_name(san.value))
                elif isinstance(san, RegisteredID):
                    alt_names.registered_id.append(san.value.dotted_string)
                elif isinstance(san, OtherName):
                    alt_names.other_name.append(format_other_name(san))

    return alt_names


def format_directory_name(directory_name_value: x509.Name) -> str:
    """Format a DirectoryName into a string.

    Args:
    ----
        directory_name_value: Directory name value to format

    Returns:
    -------
        Formatted directory name string

    """
    dn_parts = []
    for attr in directory_name_value:
        oid = attr.oid
        # Ensure bytes are decoded if needed
        value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value

        if oid == NameOID.COMMON_NAME:
            dn_parts.append(f"CN={value}")
        elif oid == NameOID.ORGANIZATION_NAME:
            dn_parts.append(f"O={value}")
        elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            dn_parts.append(f"OU={value}")
        elif oid == NameOID.COUNTRY_NAME:
            dn_parts.append(f"C={value}")
        elif oid == NameOID.STATE_OR_PROVINCE_NAME:
            dn_parts.append(f"ST={value}")
        elif oid == NameOID.LOCALITY_NAME:
            dn_parts.append(f"L={value}")
        elif oid == NameOID.EMAIL_ADDRESS:
            dn_parts.append(f"E={value}")

    return ",".join(dn_parts) if dn_parts else ""


def format_other_name(other_name: OtherName) -> str:
    """Format an OtherName into a string.

    Args:
    ----
        other_name: OtherName value to format

    Returns:
    -------
        Formatted other name string

    """
    try:
        value = other_name.value.decode("utf-8")
        return f"{other_name.type_id.dotted_string}:{value}"
    except UnicodeDecodeError:
        # If it's not UTF-8 decodable, use a hex representation
        hex_value = other_name.value.hex()
        return f"{other_name.type_id.dotted_string}:{hex_value}"


def save_certificate_to_file(cert: x509.Certificate, out_path: str) -> None:
    """Save a certificate to a file.

    Args:
    ----
        cert: Certificate to save
        out_path: Path to save the certificate to

    """
    out_file_path = Path(out_path)
    with open(out_file_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))
    console.print(f"✅ Certificate saved to [bold]{out_file_path}[/bold]")


def process_csr(
    csr_path: str,
    ca_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    validity_days: int = 365,
    out_path: str | None = None,
) -> tuple[str | None, x509.Certificate | None]:
    """Process a Certificate Signing Request."""
    try:
        # Load and validate CSR
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data)

        # Verify the CSR signature
        if not csr.is_signature_valid:
            console.print("[bold red]Error:[/bold red] CSR has an invalid signature")
            return None, None

        # Extract the hostname from the CSR's common name
        hostname = extract_hostname_from_csr(csr)
        if not hostname:
            console.print("[bold red]Error:[/bold red] Could not extract hostname from CSR")
            return None, None

        console.print(f"Processing CSR for [bold]{hostname}[/bold]")

        # Load configuration to get the hash algorithm
        config = load_config()
        hash_algorithm_name = config.get("ca", {}).get("hash_algorithm", DEFAULT_HASH_ALGORITHM)
        hash_algorithm = get_hash_algorithm(hash_algorithm_name)

        # Extract SANs from the CSR
        alt_names = extract_sans_from_csr(csr)

        # Create certificate
        cert_builder = create_certificate_builder(
            subject=csr.subject, issuer=ca_cert.subject, public_key=csr.public_key(), validity_days=validity_days
        )

        # Process and add all SANs
        san_list = process_all_sans(alt_names)

        # Add standard extensions to certificate
        cert_builder = add_standard_extensions(cert_builder=cert_builder, is_ca=False, san_list=san_list)

        # Sign the certificate
        cert = sign_certificate(cert_builder, ca_key, hash_algorithm)

        # Save the certificate if an output path is provided
        if out_path:
            save_certificate_to_file(cert, out_path)

        return hostname, cert

    except Exception as e:
        console.print(f"[bold red]Error processing CSR:[/bold red] {str(e)}")
        return None, None


def _prepare_host_config_object(
    hostname: str,
    host_config: dict[str, Any] | HostConfig,
    alt_names: AlternativeNames,
    key_algorithm: str,
    hash_algorithm: str | None,
) -> HostConfig:
    """Prepare a HostConfig object from dictionary configuration or HostConfig object.

    Args:
    ----
        hostname: The hostname
        host_config: Dictionary with host configuration or HostConfig object
        alt_names: Alternative names object
        key_algorithm: Key algorithm to use
        hash_algorithm: Hash algorithm to use

    Returns:
    -------
        HostConfig object

    """
    # If already a HostConfig, just return it with updated fields
    if isinstance(host_config, HostConfig):
        return HostConfig(
            name=hostname,
            common_name=host_config.common_name,
            organization=host_config.organization,
            organization_unit=host_config.organization_unit,
            country=host_config.country,
            state=host_config.state,
            locality=host_config.locality,
            email=host_config.email,
            alternative_names=alt_names if not alt_names.is_empty() else None,
            key_algorithm=key_algorithm,
            hash_algorithm=hash_algorithm,
        )

    # Otherwise, treat as dictionary
    return HostConfig(
        name=hostname,
        common_name=host_config.get("common_name", hostname),
        organization=host_config.get("organization"),
        organization_unit=host_config.get("organization_unit"),
        country=host_config.get("country"),
        state=host_config.get("state"),
        locality=host_config.get("locality"),
        email=host_config.get("email"),
        alternative_names=alt_names if not alt_names.is_empty() else None,
        key_algorithm=key_algorithm,
        hash_algorithm=hash_algorithm,
    )


def _prepare_alternative_names(alt_names_dict: dict[str, list[str]]) -> AlternativeNames:
    """Create an AlternativeNames object from configuration dictionary.

    Args:
    ----
        alt_names_dict: Dictionary with alternative names

    Returns:
    -------
        AlternativeNames object

    """
    alt_names = AlternativeNames()

    if alt_names_dict:
        for name_type, names in alt_names_dict.items():
            if hasattr(alt_names, name_type) and names:
                setattr(alt_names, name_type, names)

    return alt_names


@dataclass
class CertificateSaveParams:
    """Parameters for saving certificates and keys."""

    cert_path: Path
    key_path: Path
    cert: x509.Certificate
    private_key: PrivateKeyTypes
    password: str
    is_new: bool
    hostname: str


def _save_certificate_and_key(params: CertificateSaveParams) -> None:
    """Save certificate and optionally private key to disk.

    Args:
    ----
        params: Parameters for saving certificate and key

    """
    store = get_store()

    # Unlock the store
    if not store.is_unlocked:
        if not store.unlock(params.password):
            raise ValueError("Failed to unlock the store with the provided password")

    # Save cert and key
    cert_path = store.save_host_cert(params.hostname, params.cert)

    # Save key if new
    if params.is_new:
        key_path = store.save_host_key(params.hostname, params.private_key)
        console.print(f"✅ Private key saved to [bold]{key_path}[/bold]")
    else:
        key_path = store.get_host_key_path(params.hostname)

    action = "Generat" if params.is_new else "Renew"
    console.print(f"✅ Certificate {action}ed successfully for [bold]{params.hostname}[/bold]")
    console.print(f"   Certificate: [bold]{cert_path}[/bold]")
    if params.is_new:
        console.print(f"   Private key (encrypted): [bold]{key_path}[/bold]")


def _handle_existing_key(key_path: Path, key_algorithm: str) -> tuple[PrivateKeyTypes | None, str | None]:
    """Handle loading and validating an existing private key.

    Args:
    ----
        key_path: Path to the private key
        key_algorithm: Expected key algorithm

    Returns:
    -------
        Tuple of (private_key, password) or (None, None) if failed

    """
    # Initialize the store and unlock it
    store = get_store()
    if not store.unlock():
        return None, None

    password = store._password
    if not password:
        return None, None

    try:
        # Use store to load the key using the path
        with open(key_path, "rb") as f:
            key_data = f.read()

        # Need to manually load it here since we're working with a direct path
        private_key = load_pem_private_key(key_data, password=password.encode())
    except Exception as e:
        console.print(f"[bold red]Error decrypting private key:[/bold red] {str(e)}")
        return None, None

    # Verify that the existing key matches the algorithm in the config
    if not verify_key_algorithm(private_key, key_algorithm):
        console.print(
            "[bold red]Error:[/bold red] The existing key algorithm does not match the configuration. "
            "To generate a new key with the configured algorithm, use 'host rekey'."
        )
        return None, None

    return private_key, password


def _create_new_key(hostname: str, key_algorithm: str) -> tuple[PrivateKeyTypes | None, str | None]:
    """Create a new private key.

    Args:
    ----
        hostname: Hostname for logging
        key_algorithm: Key algorithm to use

    Returns:
    -------
        Tuple of (private_key, password) or (None, None) if failed

    """
    console.print(f"Generating {key_algorithm} key for {hostname}...")
    private_key = generate_key(key_algorithm=key_algorithm)

    # Get password by unlocking the store
    store = get_store()
    if not store.unlock():
        return None, None

    password = store._password
    if not password:
        return None, None

    return private_key, password


def issue_certificate(hostname: str, no_export: bool = False, do_deploy: bool = False) -> bool:
    """Issue or renew a certificate for a host."""
    # Initialize the store
    store = get_store()

    # Validate configuration first
    if not validate_config_before_operation(store.config):
        return False

    try:
        ca_key, ca_cert = load_ca_key_cert()
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return False

    # Check if hostname exists in hosts config
    try:
        host_config = get_host_config(hostname)
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] Host {hostname} not found in hosts configuration")
        return False

    # Check if certificate and key exist
    key_algorithm = host_config.key_algorithm if hasattr(host_config, "key_algorithm") else "RSA2048"
    is_new = not (store.host_cert_exists(hostname) and store.host_key_exists(hostname))

    # Handle key creation or loading
    if is_new:
        store.init()  # Ensure directories exist
        private_key, password = _create_new_key(hostname, key_algorithm)
    else:
        # Use the existing key
        key_path = store.get_host_key_path(hostname)
        private_key, password = _handle_existing_key(key_path, key_algorithm)

    if not private_key or not password:
        return False

    # Get validity period and prepare alternative names
    # Convert to new validity config approach
    if hasattr(host_config, "validity"):
        validity_days = host_config.validity.to_days()
    else:
        validity_days = 365
    if hasattr(host_config, "alternative_names") and host_config.alternative_names:
        alt_names = host_config.alternative_names
    else:
        alt_names = AlternativeNames()

    # Log operation
    action = "Generating" if is_new else "Renewing"
    console.print(f"{action} certificate for {hostname} valid for {validity_days} days...")

    # Get hash algorithm and prepare host config object
    hash_algorithm = getattr(host_config, "hash_algorithm", None)
    host_config_obj = _prepare_host_config_object(
        hostname=hostname,
        host_config=host_config,
        alt_names=alt_names,
        key_algorithm=key_algorithm,
        hash_algorithm=hash_algorithm,
    )

    # Create certificate
    cert = create_certificate(
        hostname=hostname,
        private_key=private_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        alt_names=alt_names if not alt_names.is_empty() else None,
        hash_algorithm=hash_algorithm,
        host_config=host_config_obj,
    )

    # Get certificate and key paths
    _host_dir, cert_path, key_path = get_host_paths(store, hostname)

    # Save certificate and key
    save_params = CertificateSaveParams(
        cert_path=cert_path,
        key_path=key_path,
        cert=cert,
        private_key=private_key,
        password=password,
        is_new=is_new,
        hostname=hostname,
    )
    _save_certificate_and_key(save_params)

    # Export certificate
    store = get_store()
    export_certificate(store, hostname, cert, no_export=no_export)

    # Deploy if requested
    if do_deploy:
        deploy_host(store, hostname)

    # Update inventory is done automatically by the store when saving certificates
    inventory_store = get_store()
    inventory_store.update_inventory()
    console.print("📋 Inventory updated")

    return True


def issue_all_certificates(no_export: bool = False, do_deploy: bool = False) -> bool:
    """Issue or renew certificates for all hosts in configuration."""
    # Initialize the store
    store = get_store()

    # Validate configuration first
    if not validate_config_before_operation(store.config):
        return False

    hosts_config = store.load_hosts_config()

    # Explicitly typing this as List[str] to avoid Collection[str] typing issue
    hosts: list[str] = [host["name"] for host in hosts_config.get("hosts", [])]
    if not hosts:
        console.print("[bold yellow]Warning:[/bold yellow] No hosts found in configuration")
        return False

    success_count = 0
    error_count = 0

    for hostname in hosts:
        console.print(f"\nProcessing certificate for [bold]{hostname}[/bold]...")
        try:
            if issue_certificate(hostname, no_export, do_deploy):
                success_count += 1
            else:
                error_count += 1
        except Exception as e:
            console.print(f"[bold red]Error processing {hostname}:[/bold red] {str(e)}")
            error_count += 1

    console.print(f"\n✅ Successfully processed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to process {error_count} certificates")

    return success_count > 0 and error_count == 0


def rekey_host(hostname: str, no_export: bool = False, do_deploy: bool = False) -> bool:
    """Generate a new key and certificate for a host."""
    # Initialize the store
    store = get_store()

    # Validate configuration first
    if not validate_config_before_operation(store.config):
        return False

    try:
        ca_key, ca_cert = load_ca_key_cert()
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return False

    # Check if hostname exists in hosts config
    try:
        host_config = get_host_config(hostname)
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] Host {hostname} not found in hosts configuration")
        return False

    # Get host paths from utility function
    host_dir, cert_path, key_path = get_host_paths(store, hostname)
    host_dir.mkdir(parents=True, exist_ok=True)

    # Generate new key
    key_algorithm = host_config.key_algorithm if hasattr(host_config, "key_algorithm") else "RSA2048"
    private_key, password = _create_new_key(hostname, key_algorithm)
    if not private_key or not password:
        return False

    # Get validity period and prepare alternative names
    # Convert to new validity config approach
    if hasattr(host_config, "validity"):
        validity_days = host_config.validity.to_days()
    else:
        validity_days = 365
    if hasattr(host_config, "alternative_names") and host_config.alternative_names:
        alt_names = host_config.alternative_names
    else:
        alt_names = AlternativeNames()

    # Log operation
    console.print(f"Generating certificate for {hostname} valid for {validity_days} days...")

    # Get hash algorithm and prepare host config object
    hash_algorithm = getattr(host_config, "hash_algorithm", None)
    host_config_obj = _prepare_host_config_object(
        hostname=hostname,
        host_config=host_config,
        alt_names=alt_names,
        key_algorithm=key_algorithm,
        hash_algorithm=hash_algorithm,
    )

    # Create certificate
    cert = create_certificate(
        hostname=hostname,
        private_key=private_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        alt_names=alt_names if not alt_names.is_empty() else None,
        hash_algorithm=hash_algorithm,
        host_config=host_config_obj,
    )

    # Save certificate and key (always save both for rekey)
    save_params = CertificateSaveParams(
        cert_path=cert_path,
        key_path=key_path,
        cert=cert,
        private_key=private_key,
        password=password,
        is_new=True,  # Always save key for rekey
        hostname=hostname,
    )
    _save_certificate_and_key(save_params)

    # Additional message specific to rekeying
    console.print(f"✅ Certificate and key rekeyed successfully for [bold]{hostname}[/bold]")

    # Export certificate
    store = get_store()
    export_certificate(store, hostname, cert, no_export=no_export)

    # Deploy if requested
    if do_deploy:
        deploy_host(store, hostname)

    # Update inventory is done automatically by the store when saving certificates
    inventory_store = get_store()
    inventory_store.update_inventory()
    console.print("📋 Inventory updated")

    return True


def rekey_all_hosts(no_export: bool = False, do_deploy: bool = False) -> bool:
    """Rekey all hosts in configuration."""
    # Initialize the store
    store = get_store()

    # Validate configuration first
    if not validate_config_before_operation(store.config):
        return False

    hosts_config = store.load_hosts_config()

    # Explicitly typing this as List[str] to avoid Collection[str] typing issue
    hosts: list[str] = [host["name"] for host in hosts_config.get("hosts", [])]
    if not hosts:
        console.print("[bold yellow]Warning:[/bold yellow] No hosts found in configuration")
        return False

    success_count = 0
    error_count = 0

    for hostname in hosts:
        console.print(f"\nRekeying certificate for [bold]{hostname}[/bold]...")
        try:
            if rekey_host(hostname, no_export, do_deploy):
                success_count += 1
            else:
                error_count += 1
        except Exception as e:
            console.print(f"[bold red]Error rekeying {hostname}:[/bold red] {str(e)}")
            error_count += 1

    console.print(f"\n✅ Successfully rekeyed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to rekey {error_count} certificates")

    return success_count > 0 and error_count == 0


def import_host_key(hostname: str, key_path: str) -> bool:
    """Import an existing private key for a host."""
    # Initialize the store
    store = get_store()

    # Check if hostname exists in hosts config
    hosts_config = store.load_hosts_config()
    host_exists = False

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_exists = True
            break

    if not host_exists:
        console.print(f"[bold yellow]Warning:[/bold yellow] Host {hostname} not found in hosts configuration")
        console.print("You will need to add it to the configuration file manually.")

    # Check if source key file exists
    src_key_path = Path(key_path)
    if not src_key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Key file not found: {key_path}")
        return False

    # Check if host already has certificate or key
    if store.host_cert_exists(hostname) or store.host_key_exists(hostname):
        if not click.confirm(f"Certificate or key for {hostname} already exists. Overwrite?", default=False):
            return False

    # Make sure the store is initialized
    store.init()

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
            src_password = click.prompt(
                "Enter password of key to import", hide_input=True, default="", show_default=False
            )
            try:
                private_key = load_pem_private_key(key_data, password=src_password.encode() if src_password else None)
            except Exception as e:
                console.print(f"[bold red]Error decrypting key to import:[/bold red] {str(e)}")
                return False
    except Exception as e:
        console.print(f"[bold red]Error loading key to import:[/bold red] {str(e)}")
        return False

    # Unlock the store with the destination password
    if not store.unlock():
        return False

    # Save the key using the store API
    key_dest_path = store.save_host_key(hostname, private_key)

    console.print(f"✅ Key imported successfully for [bold]{hostname}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{key_dest_path}[/bold]")

    return True


def export_host_key(hostname: str, out_path: str | None = None) -> bool:
    """Export an unencrypted private key for a host."""
    store = get_store()

    if not store.host_key_exists(hostname):
        console.print(f"[bold red]Error:[/bold red] Key for {hostname} not found")
        return False

    # Unlock the store
    if not store.unlock():
        return False

    try:
        if out_path:
            # Export the key to file using the store API (decrypted)
            if store.export_host_key(hostname, out_path, decrypt=True):
                console.print(f"✅ Unencrypted key exported to [bold]{out_path}[/bold]")
                return True
            else:
                console.print(f"[bold red]Error exporting key for {hostname}[/bold red]")
                return False
        else:
            # For stdout display, we need to load the key and format it
            private_key = store.load_host_key(hostname)
            if private_key:
                # Convert to unencrypted PEM format
                unencrypted_key_data = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
                # Write to stdout
                console.print(unencrypted_key_data.decode())
                return True
            else:
                console.print(f"[bold red]Error loading key for {hostname}[/bold red]")
                return False
    except Exception as e:
        console.print(f"[bold red]Error exporting key for {hostname}:[/bold red] {str(e)}")
        return False


def calculate_days_remaining(expiry_date_str: str) -> int | None:
    """Calculate days remaining until expiration.

    Args:
    ----
        expiry_date_str: ISO format date string

    Returns:
    -------
        Days remaining as integer or None if date is invalid

    """
    try:
        now = datetime.datetime.now(datetime.UTC)
        expiry_date = datetime.datetime.fromisoformat(expiry_date_str)
        expiry_date = expiry_date.replace(tzinfo=datetime.UTC)
        return (expiry_date - now).days
    except (ValueError, TypeError):
        return None


def filter_hosts_by_expiry(
    hosts: list[dict[str, Any]], expired: bool = False, expiring_days: int | None = None
) -> list[dict[str, Any]]:
    """Filter hosts based on expiration criteria.

    Args:
    ----
        hosts: List of host dictionaries
        expired: Only include expired certificates if True
        expiring_days: Only include certificates expiring within this many days

    Returns:
    -------
        Filtered list of hosts

    """
    filtered_hosts = []

    for host in hosts:
        days_remaining = None
        not_after = host.get("not_after", "Unknown")

        if not_after != "Unknown":
            days_remaining = calculate_days_remaining(not_after)

            if days_remaining is not None:
                # Apply filters
                if expired and days_remaining >= 0:
                    continue

                if expiring_days is not None and days_remaining > expiring_days:
                    continue

                # Add days_remaining to host info
                host["days_remaining"] = days_remaining
                filtered_hosts.append(host)
            elif not expired and expiring_days is None:
                # Include hosts with invalid dates if not filtering
                filtered_hosts.append(host)
        elif not expired and expiring_days is None:
            # Include hosts with unknown expiry if not filtering
            filtered_hosts.append(host)

    return filtered_hosts


def output_certificate_json(
    ca_info: dict[str, Any],
    filtered_hosts: list[dict[str, Any]],
    inventory: dict[str, Any],
    ca_days_remaining: int | None = None,
) -> None:
    """Output certificate information in JSON format.

    Args:
    ----
        ca_info: CA certificate information
        filtered_hosts: Filtered list of hosts
        inventory: Full inventory data
        ca_days_remaining: Days remaining until CA expiration

    """
    result = {
        "ca": ca_info.copy(),  # Use copy to avoid modifying original
        "hosts": filtered_hosts,
        "last_update": inventory.get("last_update", "Unknown"),
    }

    if ca_days_remaining is not None:
        result["ca"]["days_remaining"] = ca_days_remaining

    console.print(json.dumps(result, indent=2))


def create_ca_table(ca_info: dict[str, Any], ca_days_remaining: int | None) -> Table:
    """Create a table with CA certificate information.

    Args:
    ----
        ca_info: CA certificate information
        ca_days_remaining: Days remaining until CA expiration

    Returns:
    -------
        Rich Table object with CA information

    """
    ca_table = Table(title="CA Certificate")
    ca_table.add_column("Serial")
    ca_table.add_column("Expiration Date")
    ca_table.add_column("Days Remaining")
    ca_table.add_column("Fingerprint")

    # Format CA expiration with color based on how soon it expires
    ca_expiry_formatted = ca_info.get("not_after", "Unknown")
    days_formatted = "Unknown"

    if ca_days_remaining is not None:
        days_formatted = format_certificate_expiry(ca_days_remaining)

    ca_table.add_row(
        ca_info.get("serial", "Unknown"),
        ca_expiry_formatted,
        days_formatted,
        ca_info.get("fingerprint", "Unknown"),
    )

    return ca_table


def create_hosts_table(filtered_hosts: list[dict[str, Any]]) -> Table:
    """Create a table with host certificate information.

    Args:
    ----
        filtered_hosts: List of host dictionaries with certificate information

    Returns:
    -------
        Rich Table object with host information

    """
    host_table = Table(title="Host Certificates")
    host_table.add_column("Hostname")
    host_table.add_column("Serial")
    host_table.add_column("Expiration Date")
    host_table.add_column("Days Remaining")
    host_table.add_column("Fingerprint")
    host_table.add_column("Renewals")

    # Sort hosts by name
    sorted_hosts = sorted(filtered_hosts, key=lambda x: x.get("name", ""))

    for host in sorted_hosts:
        name = host.get("name", "Unknown")
        serial = host.get("serial", "Unknown")
        not_after = host.get("not_after", "Unknown")
        fingerprint = host.get("fingerprint", "Unknown")
        renewal_count = str(host.get("renewal_count", 0))
        days_remaining = host.get("days_remaining", "Unknown")

        # Format days remaining with color using utility function
        days_formatted = "Unknown"
        if days_remaining != "Unknown" and days_remaining is not None:
            days_formatted = format_certificate_expiry(days_remaining)

        host_table.add_row(name, serial, not_after, days_formatted, fingerprint, renewal_count)

    return host_table


def list_certificates(expired: bool = False, expiring_days: int | None = None, json_output: bool = False) -> None:
    """List all certificates with their expiration dates."""
    # Initialize the store
    store = get_store()

    # Ensure inventory is up to date
    store.update_inventory()

    # Load inventory
    inventory = store._load_inventory()

    # Display CA information
    ca_info = inventory.get("ca", {})
    if not ca_info:
        console.print("[bold red]Error:[/bold red] CA information not found in inventory")
        return

    # Calculate days until CA expiration
    ca_days_remaining = None
    if "not_after" in ca_info:
        ca_days_remaining = calculate_days_remaining(ca_info["not_after"])

    # Filter hosts based on expiration criteria
    hosts = inventory.get("hosts", [])
    filtered_hosts = filter_hosts_by_expiry(hosts, expired, expiring_days)

    # Output JSON if requested
    if json_output:
        output_certificate_json(ca_info, filtered_hosts, inventory, ca_days_remaining)
        return

    # Display CA information in table format
    ca_table = create_ca_table(ca_info, ca_days_remaining)
    console.print(ca_table)

    # Display host certificates
    if not filtered_hosts:
        console.print("\nNo host certificates match the criteria")
        return

    # Create and display hosts table
    host_table = create_hosts_table(filtered_hosts)
    console.print("\n")
    console.print(host_table)

    # Show last update time
    last_update = inventory.get("last_update", "Unknown")
    console.print(f"\nLast updated: {last_update}")


def deploy_all_hosts() -> bool:
    """Deploy all host certificates."""
    # Initialize the store
    store = get_store()

    hosts_config = store.load_hosts_config()

    # Explicitly typing this as List[str] to avoid Collection[str] typing issue
    hosts: list[str] = [host["name"] for host in hosts_config.get("hosts", [])]
    if not hosts:
        console.print("[bold yellow]Warning:[/bold yellow] No hosts found in configuration")
        return False

    success_count = 0
    error_count = 0

    for hostname in hosts:
        console.print(f"\nDeploying certificate for [bold]{hostname}[/bold]...")
        try:
            if deploy_host(store, hostname):
                success_count += 1
            else:
                error_count += 1
        except Exception as e:
            console.print(f"[bold red]Error deploying {hostname}:[/bold red] {str(e)}")
            error_count += 1

    console.print(f"\n✅ Successfully deployed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to deploy {error_count} certificates")

    return success_count > 0
