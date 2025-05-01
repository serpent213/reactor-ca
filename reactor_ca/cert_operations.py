"""Certificate operations for ReactorCA."""

import datetime
from pathlib import Path
from typing import Any

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
    decrypt_key,
    encrypt_key,
    generate_key,
    get_confirmed_password,
    get_hash_algorithm,
    verify_key_algorithm,
)
from reactor_ca.config_validator import validate_config_before_operation
from reactor_ca.paths import CA_DIR
from reactor_ca.utils import (
    add_standard_extensions,
    calculate_validity_days,
    create_certificate_builder,
    create_subject_from_config,
    format_certificate_expiry,
    get_host_paths,
    get_password,
    load_config,
    load_hosts_config,
    load_inventory,
    process_all_sans,
    run_deploy_command,
    save_inventory,
    sign_certificate,
    update_inventory,
    update_inventory_for_cert,
)

console = Console()


def load_ca_key_cert() -> tuple[Any | None, x509.Certificate | None]:
    """Load the CA key and certificate."""
    # Check if CA exists
    ca_cert_path = CA_DIR / "ca.crt"
    ca_key_path = CA_DIR / "ca.key.enc"

    if not ca_cert_path.exists() or not ca_key_path.exists():
        console.print(
            "[bold red]Error:[/bold red] " + "CA certificate or key not found. Please initialize the CA first."
        )
        return None, None

    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Get password and decrypt CA key
    password = get_password()
    if not password:
        return None, None

    try:
        ca_key = decrypt_key(ca_key_path, password)
    except Exception as e:
        console.print(f"[bold red]Error decrypting CA key:[/bold red] {str(e)}")
        return None, None

    return ca_key, ca_cert


def create_certificate(
    private_key: Any,
    hostname: str,
    ca_key: Any,
    ca_cert: x509.Certificate,
    validity_days: int = 365,
    alt_names: dict[str, list[str]] | None = None,
    hash_algorithm: str | None = None,
    host_config: dict[str, Any] | None = None,
) -> x509.Certificate:
    """Create a certificate signed by the CA."""
    config = load_config()

    # Get hash algorithm from config or parameter
    if hash_algorithm is None:
        hash_algorithm = config.get("ca", {}).get("hash_algorithm", DEFAULT_HASH_ALGORITHM)

    hash_algo = get_hash_algorithm(hash_algorithm)

    # Create subject using utility function
    subject = create_subject_from_config(hostname, config, host_config)

    # Create certificate builder
    cert_builder = create_certificate_builder(
        subject=subject, issuer=ca_cert.subject, public_key=private_key.public_key(), validity_days=validity_days
    )

    # Process Subject Alternative Names if provided
    san_list = []
    if alt_names:
        san_list = process_all_sans(alt_names)

    # Add standard extensions to certificate
    cert_builder = add_standard_extensions(cert_builder=cert_builder, is_ca=False, san_list=san_list)

    # Sign the certificate
    cert = sign_certificate(cert_builder, ca_key, hash_algo)

    return cert


def export_certificate(
    hostname: str, certificate: x509.Certificate, key: Any | None = None, chain: bool = True, no_export: bool = False
) -> bool:
    """Export a certificate and optionally its private key and chain to the configured location."""
    if no_export:
        console.print(f"Certificate export skipped for [bold]{hostname}[/bold] (--no-export flag)")
        return True  # Return True to allow deployment to proceed

    hosts_config = load_hosts_config()
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
        ca_cert_path = CA_DIR / "ca.crt"
        try:
            with open(ca_cert_path, "rb") as f:
                ca_cert_data = f.read()

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


def deploy_host(hostname: str) -> bool:
    """Run the deployment script for a host."""
    hosts_config = load_hosts_config()
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
    return run_deploy_command(hostname, deploy_command)


def process_csr(
    csr_path: str, ca_key: Any, ca_cert: x509.Certificate, validity_days: int = 365, out_path: str | None = None
) -> tuple[str | None, x509.Certificate | None]:
    """Process a Certificate Signing Request."""
    try:
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data)

        # Verify the CSR signature
        if not csr.is_signature_valid:
            console.print("[bold red]Error:[/bold red] CSR has an invalid signature")
            return None, None

        # Extract the hostname from the CSR's common name
        hostname = None
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                # Handle both string and bytes value types
                hostname = attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
                break

        if not hostname:
            console.print("[bold red]Error:[/bold red] Could not extract hostname from CSR")
            return None, None

        console.print(f"Processing CSR for [bold]{hostname}[/bold]")

        # Load configuration to get the hash algorithm
        config = load_config()
        hash_algorithm_name = config.get("ca", {}).get("hash_algorithm", DEFAULT_HASH_ALGORITHM)
        hash_algorithm = get_hash_algorithm(hash_algorithm_name)

        # Extract any SANs from the CSR
        alt_names: dict[str, list[str]] = {
            "dns": [],
            "ip": [],
            "email": [],
            "uri": [],
            "directory_name": [],
            "registered_id": [],
            "other_name": [],
        }

        for ext in csr.extensions:
            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for san in ext.value:
                    if isinstance(san, x509.DNSName):
                        alt_names["dns"].append(san.value)
                    elif isinstance(san, x509.IPAddress):
                        alt_names["ip"].append(str(san.value))
                    elif isinstance(san, x509.RFC822Name):
                        alt_names["email"].append(san.value)
                    elif isinstance(san, UniformResourceIdentifier):
                        alt_names["uri"].append(san.value)
                    elif isinstance(san, DirectoryName):
                        # Format the directory name as a string for display
                        dn_parts = []
                        # Properly type the DirectoryName value as Name
                        directory_name_value = san.value
                        for attr in directory_name_value:
                            # Each attribute in a Name has an oid property
                            oid = attr.oid
                            if oid == NameOID.COMMON_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"CN={value}")
                            elif oid == NameOID.ORGANIZATION_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"O={value}")
                            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"OU={value}")
                            elif oid == NameOID.COUNTRY_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"C={value}")
                            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"ST={value}")
                            elif oid == NameOID.LOCALITY_NAME:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"L={value}")
                            elif oid == NameOID.EMAIL_ADDRESS:
                                # Ensure bytes are decoded if needed
                                value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value
                                dn_parts.append(f"E={value}")

                        if dn_parts:
                            alt_names["directory_name"].append(",".join(dn_parts))
                    elif isinstance(san, RegisteredID):
                        alt_names["registered_id"].append(san.value.dotted_string)
                    elif isinstance(san, OtherName):
                        # Format as OID:value
                        try:
                            value = san.value.decode("utf-8")
                            alt_names["other_name"].append(f"{san.type_id.dotted_string}:{value}")
                        except UnicodeDecodeError:
                            # If it's not UTF-8 decodable, use a hex representation
                            hex_value = san.value.hex()
                            alt_names["other_name"].append(f"{san.type_id.dotted_string}:{hex_value}")

        # Create certificate builder
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
            out_file_path = Path(out_path)
            with open(out_file_path, "wb") as f:
                f.write(cert.public_bytes(encoding=Encoding.PEM))
            console.print(f"✅ Certificate saved to [bold]{out_file_path}[/bold]")

        return hostname, cert

    except Exception as e:
        console.print(f"[bold red]Error processing CSR:[/bold red] {str(e)}")
        return None, None


def issue_certificate(hostname: str, no_export: bool = False, do_deploy: bool = False) -> bool:
    """Issue or renew a certificate for a host."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before issuing certificates."
        )
        return False

    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return False

    # Check if hostname exists in hosts config
    hosts_config = load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold red]Error:[/bold red] Host {hostname} not found in hosts configuration")
        return False

    # Get host paths from utility function
    host_dir, cert_path, key_path = get_host_paths(hostname)

    # Get the configured key algorithm
    key_algorithm = host_config.get("key_algorithm", "RSA2048")

    is_new = False

    if not cert_path.exists() or not key_path.exists():
        # This is a new certificate
        is_new = True
        host_dir.mkdir(parents=True, exist_ok=True)

        # Generate key
        console.print(f"Generating {key_algorithm} key for {hostname}...")
        private_key = generate_key(key_algorithm=key_algorithm)

        # Get password with confirmation for key encryption

        password = get_confirmed_password()
        if not password:
            return False
    else:
        # This is a renewal
        # Get password and decrypt private key
        password = get_password()
        if not password:
            return False

        try:
            private_key = decrypt_key(key_path, password)
        except Exception as e:
            console.print(f"[bold red]Error decrypting private key:[/bold red] {str(e)}")
            return False

        # Verify that the existing key matches the algorithm in the config

        if not verify_key_algorithm(private_key, key_algorithm):
            console.print(
                "[bold red]Error:[/bold red] The existing key algorithm does not match the configuration. "
                "To generate a new key with the configured algorithm, use 'host rekey'."
            )
            return False

    # Get validity period
    validity_days = calculate_validity_days(host_config.get("validity", {"days": 365}))

    # Get alternative names
    alt_names = host_config.get("alternative_names", {})

    action = "Generating" if is_new else "Renewing"
    console.print(f"{action} certificate for {hostname} valid for {validity_days} days...")

    # Get hash algorithm if specified in host config
    hash_algorithm = host_config.get("hash_algorithm")

    # Create certificate
    cert = create_certificate(
        private_key,
        hostname,
        ca_key,
        ca_cert,
        validity_days,
        alt_names,
        hash_algorithm,
        host_config,
    )

    # Save key if new or certificate
    if is_new:
        with open(key_path, "wb") as f:
            f.write(encrypt_key(private_key, password))
        console.print(f"✅ Private key saved to [bold]{key_path}[/bold]")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

    console.print(f"✅ Certificate {action.lower()[:-3]}ed successfully for [bold]{hostname}[/bold]")
    console.print(f"   Certificate: [bold]{cert_path}[/bold]")
    if is_new:
        console.print(f"   Private key (encrypted): [bold]{key_path}[/bold]")

    # Export certificate
    export_certificate(hostname, cert, no_export=no_export)

    # Deploy if requested (regardless of export success)
    if do_deploy:
        deploy_host(hostname)

    # Update inventory using utility function
    inventory = load_inventory()
    inventory = update_inventory_for_cert(
        inventory=inventory, hostname=hostname, cert=cert, rekeyed=False, renewal_count_increment=1
    )
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def issue_all_certificates(no_export: bool = False, do_deploy: bool = False) -> bool:
    """Issue or renew certificates for all hosts in configuration."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before issuing certificates."
        )
        return False

    hosts_config = load_hosts_config()

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
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before rekeying certificates."
        )
        return False

    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return False

    # Check if hostname exists in hosts config
    hosts_config = load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold red]Error:[/bold red] Host {hostname} not found in hosts configuration")
        return False

    # Get host paths from utility function
    host_dir, cert_path, key_path = get_host_paths(hostname)

    # Create directory if needed
    host_dir.mkdir(parents=True, exist_ok=True)

    # Generate new key
    key_algorithm = host_config.get("key_algorithm", "RSA2048")

    console.print(f"Generating new {key_algorithm} key for {hostname}...")
    private_key = generate_key(key_algorithm=key_algorithm)

    # Get password for key encryption
    password = get_password()
    if not password:
        return False

    # Get validity period
    validity_days = calculate_validity_days(host_config.get("validity", {"days": 365}))

    # Get alternative names
    alt_names = host_config.get("alternative_names", {})

    # Create certificate
    console.print(f"Generating certificate for {hostname} valid for {validity_days} days...")
    cert = create_certificate(
        private_key,
        hostname,
        ca_key,
        ca_cert,
        validity_days,
        alt_names,
        host_config=host_config,
    )

    # Save key and certificate
    with open(key_path, "wb") as f:
        f.write(encrypt_key(private_key, password))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

    console.print(f"✅ Certificate and key rekeyed successfully for [bold]{hostname}[/bold]")
    console.print(f"   Certificate: [bold]{cert_path}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{key_path}[/bold]")

    # Export certificate
    export_certificate(hostname, cert, no_export=no_export)

    # Deploy if requested (regardless of export success)
    if do_deploy:
        deploy_host(hostname)

    # Update inventory using utility function
    inventory = load_inventory()
    inventory = update_inventory_for_cert(
        inventory=inventory, hostname=hostname, cert=cert, rekeyed=True, renewal_count_increment=1
    )
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def rekey_all_hosts(no_export: bool = False, do_deploy: bool = False) -> bool:
    """Rekey all hosts in configuration."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print(
            "[bold red]Error:[/bold red] "
            + "Configuration validation failed. Please correct the configuration before rekeying certificates."
        )
        return False

    hosts_config = load_hosts_config()

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


def import_host_key(hostname: str, key_path: str, password: str | None = None) -> bool:
    """Import an existing private key for a host."""
    # Check if hostname exists in hosts config
    hosts_config = load_hosts_config()
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

    # Get host paths from utility function
    host_dir, cert_path, key_dest_path = get_host_paths(hostname)

    if cert_path.exists() or key_dest_path.exists():
        if not click.confirm(f"Certificate or key for {hostname} already exists. Overwrite?", default=False):
            return False

    # Create host directory if it doesn't exist
    host_dir.mkdir(parents=True, exist_ok=True)

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

    # Get password for encrypting the key
    dest_password = password if password is not None else get_password()
    if not dest_password:
        return False

    # Validate against CA key password to ensure consistent encryption
    ca_key_path = CA_DIR / "ca.key.enc"
    if ca_key_path.exists():
        try:
            decrypt_key(ca_key_path, dest_password)
        except Exception:
            console.print("[bold red]Error:[/bold red] The provided password does not match the CA key password")
            return False

    # Encrypt and save the key
    with open(key_dest_path, "wb") as f:
        f.write(encrypt_key(private_key, dest_password))

    console.print(f"✅ Key imported successfully for [bold]{hostname}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{key_dest_path}[/bold]")

    return True


def export_host_key(hostname: str, out_path: str | None = None) -> bool:
    """Export an unencrypted private key for a host."""
    # Get host paths from utility function
    host_dir, cert_path, key_path = get_host_paths(hostname)

    if not key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Key for {hostname} not found")
        return False

    # Get password and decrypt the key
    password = get_password()
    if not password:
        return False

    try:
        private_key = decrypt_key(key_path, password)
    except Exception as e:
        console.print(f"[bold red]Error decrypting key:[/bold red] {str(e)}")
        return False

    # Export the unencrypted key
    # Cast to the appropriate type for private_bytes method
    pk_typed: PrivateKeyTypes = private_key
    unencrypted_key_data = pk_typed.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    if out_path:
        # Write to file
        out_file_path = Path(out_path)
        try:
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file_path, "wb") as f:
                f.write(unencrypted_key_data)
            console.print(f"✅ Unencrypted key exported to [bold]{out_file_path}[/bold]")
        except Exception as e:
            console.print(f"[bold red]Error writing key to file:[/bold red] {str(e)}")
            return False
    else:
        # Print to stdout
        console.print(unencrypted_key_data.decode("utf-8"))

    return True


def list_certificates(expired: bool = False, expiring_days: int | None = None, json_output: bool = False) -> None:
    """List all certificates with their expiration dates."""
    # Ensure inventory is up to date
    update_inventory()

    # Load inventory
    inventory = load_inventory()

    # Display CA information
    ca_info = inventory.get("ca", {})
    if not ca_info:
        console.print("[bold red]Error:[/bold red] CA information not found in inventory")
        return

    # Calculate days until CA expiration
    now = datetime.datetime.now(datetime.UTC)
    ca_days_remaining = None

    if "not_after" in ca_info:
        try:
            ca_expiry_date = datetime.datetime.fromisoformat(ca_info["not_after"])
            ca_expiry_date = ca_expiry_date.replace(tzinfo=datetime.UTC)
            ca_days_remaining = (ca_expiry_date - now).days
        except (ValueError, TypeError):
            pass

    # Filter hosts based on expiration criteria
    hosts = inventory.get("hosts", [])
    filtered_hosts = []

    for host in hosts:
        days_remaining = None
        not_after = host.get("not_after", "Unknown")

        if not_after != "Unknown":
            try:
                expiry_date = datetime.datetime.fromisoformat(not_after)
                expiry_date = expiry_date.replace(tzinfo=datetime.UTC)
                days_remaining = (expiry_date - now).days

                # Apply filters
                if expired and days_remaining >= 0:
                    continue

                if expiring_days is not None and days_remaining > expiring_days:
                    continue

                host["days_remaining"] = days_remaining
                filtered_hosts.append(host)
            except (ValueError, TypeError):
                # Include hosts with invalid dates if not filtering
                if not expired and expiring_days is None:
                    filtered_hosts.append(host)
        elif not expired and expiring_days is None:
            # Include hosts with unknown expiry if not filtering
            filtered_hosts.append(host)

    # Output JSON if requested
    if json_output:
        import json

        result = {
            "ca": ca_info,
            "hosts": filtered_hosts,
            "last_update": inventory.get("last_update", "Unknown"),
        }
        if ca_days_remaining is not None:
            ca_info["days_remaining"] = ca_days_remaining
        console.print(json.dumps(result, indent=2))
        return

    # Display in tables
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

    console.print(ca_table)

    # Display host certificates
    if not filtered_hosts:
        console.print("\nNo host certificates match the criteria")
        return

    host_table = Table(title="Host Certificates")
    host_table.add_column("Hostname")
    host_table.add_column("Serial")
    host_table.add_column("Expiration Date")
    host_table.add_column("Days Remaining")
    host_table.add_column("Fingerprint")
    host_table.add_column("Renewals")

    # Sort hosts by name
    filtered_hosts.sort(key=lambda x: x.get("name", ""))

    for host in filtered_hosts:
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

    console.print("\n")
    console.print(host_table)

    # Show last update time
    last_update = inventory.get("last_update", "Unknown")
    console.print(f"\nLast updated: {last_update}")


def deploy_all_hosts() -> bool:
    """Deploy all host certificates."""
    hosts_config = load_hosts_config()

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
            if deploy_host(hostname):
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
