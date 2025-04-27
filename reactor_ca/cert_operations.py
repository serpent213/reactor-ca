"""Certificate operations for ReactorCA."""

import datetime
import ipaddress
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.table import Table

from reactor_ca.ca_operations import (
    decrypt_key,
    encrypt_key,
    generate_key,
)
from reactor_ca.utils import (
    get_password,
    load_config,
    load_hosts_config,
    load_inventory,
    save_inventory,
    update_inventory,
)

console = Console()

def load_ca_key_cert():
    """Load the CA key and certificate."""
    # Check if CA exists
    ca_cert_path = Path("certs/ca/ca.crt")
    ca_key_path = Path("certs/ca/ca.key.enc")

    if not ca_cert_path.exists() or not ca_key_path.exists():
        console.print("[bold red]Error:[/bold red] CA certificate or key not found. Please initialize the CA first.")
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
    private_key,
    hostname,
    ca_key,
    ca_cert,
    validity_days=365,
    alt_names=None,
):
    """Create a certificate signed by the CA."""
    config = load_config()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config["ca"]["organization"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config["ca"]["organization_unit"]),
        x509.NameAttribute(NameOID.COUNTRY_NAME, config["ca"]["country"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config["ca"]["state"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config["ca"]["locality"]),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, config["ca"]["email"]),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
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
    )

    # Add extended key usage
    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )

    # Add subject alternative names
    if alt_names:
        san_list = []

        # Add DNS names
        if "dns" in alt_names:
            for dns_name in alt_names["dns"]:
                san_list.append(x509.DNSName(dns_name))

        # Add IP addresses
        if "ip" in alt_names:
            for ip in alt_names["ip"]:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    san_list.append(x509.IPAddress(ip_obj))
                except ValueError:
                    console.print(f"[yellow]Warning:[/yellow] Invalid IP address {ip}, skipping")

        # Only add the extension if we have SANs
        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

    # Sign the certificate
    cert = cert_builder.sign(ca_key, hashes.SHA256())

    return cert


def process_csr(csr_path, ca_key, ca_cert, validity_days=365):
    """Process a Certificate Signing Request."""
    try:
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data)

        # Verify the CSR signature
        if not csr.is_signature_valid:
            console.print("[bold red]Error:[/bold red] CSR has an invalid signature")
            return None

        # Extract the hostname from the CSR's common name
        hostname = None
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                hostname = attr.value
                break

        if not hostname:
            console.print("[bold red]Error:[/bold red] Could not extract hostname from CSR")
            return None

        console.print(f"Processing CSR for [bold]{hostname}[/bold]")

        # Extract any SANs from the CSR
        alt_names = {"dns": [], "ip": []}
        for ext in csr.extensions:
            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for san in ext.value:
                    if isinstance(san, x509.DNSName):
                        alt_names["dns"].append(san.value)
                    elif isinstance(san, x509.IPAddress):
                        alt_names["ip"].append(str(san.value))

        # Create certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
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
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
        )

        # Add SANs from CSR if any
        san_list = []
        if alt_names["dns"] or alt_names["ip"]:
            for dns_name in alt_names["dns"]:
                san_list.append(x509.DNSName(dns_name))

            for ip in alt_names["ip"]:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    san_list.append(x509.IPAddress(ip_obj))
                except ValueError:
                    console.print(f"[yellow]Warning:[/yellow] Invalid IP address {ip}, skipping")

            if san_list:
                cert_builder = cert_builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False,
                )

        # Sign the certificate
        cert = cert_builder.sign(ca_key, hashes.SHA256())

        return hostname, cert

    except Exception as e:
        console.print(f"[bold red]Error processing CSR:[/bold red] {str(e)}")
        return None, None


def generate_certificate(hostname):
    """Generate a new certificate for a host."""
    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return

    # Check if hostname exists in hosts config
    hosts_config = load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold red]Error:[/bold red] Host {hostname} not found in hosts configuration")
        return

    # Check if certificate already exists
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_path = host_dir / "cert.key.enc"

    if cert_path.exists() or key_path.exists():
        if not click.confirm(f"Certificate for {hostname} already exists. Overwrite?", default=False):
            return

    # Create host directory if it doesn't exist
    host_dir.mkdir(parents=True, exist_ok=True)

    # Generate key
    key_algo = host_config.get("key", {}).get("algorithm", "RSA")
    key_size = host_config.get("key", {}).get("size", 2048)

    console.print(f"Generating {key_algo} key...")
    private_key = generate_key(algorithm=key_algo, size=key_size)

    # Get validity period
    validity_days = host_config.get("validity_days", 365)

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
    )

    # Get password (reuse the one from CA key decryption)
    password = get_password()
    if not password:
        return

    # Save encrypted key and certificate
    with open(key_path, "wb") as f:
        f.write(encrypt_key(private_key, password))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

    console.print(f"✅ Certificate generated successfully for [bold]{hostname}[/bold]")
    console.print(f"  Certificate: [bold]{cert_path}[/bold]")
    console.print(f"  Private key (encrypted): [bold]{key_path}[/bold]")

    # Deploy certificate if destination specified
    if "destination" in host_config and host_config["destination"]:
        dest_path = Path(host_config["destination"])

        # Ensure parent directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy certificate to destination
        try:
            with open(cert_path, "rb") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())
            console.print(f"✅ Certificate deployed to [bold]{dest_path}[/bold]")
        except Exception as e:
            console.print(f"[bold red]Error deploying certificate:[/bold red] {str(e)}")

    # Update inventory
    update_inventory()
    console.print("📋 Inventory updated")


def renew_certificate(hostname):
    """Renew a certificate for a host."""
    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return

    # Check if certificate exists
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_path = host_dir / "cert.key.enc"

    if not cert_path.exists() or not key_path.exists():
        console.print(f"[bold red]Error:[/bold red] Certificate for {hostname} not found")
        return

    # Load hosts config
    hosts_config = load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold yellow]Warning:[/bold yellow] Host {hostname} not found in hosts configuration")
        host_config = {"name": hostname, "validity_days": 365}

    # Get validity period
    validity_days = host_config.get("validity_days", 365)

    # Load existing certificate to get info
    with open(cert_path, "rb") as f:
        old_cert = x509.load_pem_x509_certificate(f.read())

    # Get password and decrypt private key
    password = get_password()
    if not password:
        return

    try:
        private_key = decrypt_key(key_path, password)
    except Exception as e:
        console.print(f"[bold red]Error decrypting private key:[/bold red] {str(e)}")
        return

    # Extract existing SANs if any
    alt_names = {"dns": [], "ip": []}
    for ext in old_cert.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for san in ext.value:
                if isinstance(san, x509.DNSName):
                    alt_names["dns"].append(san.value)
                elif isinstance(san, x509.IPAddress):
                    alt_names["ip"].append(str(san.value))

    # If host_config has alternative_names, use those instead
    if "alternative_names" in host_config:
        alt_names = host_config["alternative_names"]

    # Create new certificate
    console.print(f"Renewing certificate for {hostname} valid for {validity_days} days...")
    new_cert = create_certificate(
        private_key,
        hostname,
        ca_key,
        ca_cert,
        validity_days,
        alt_names,
    )

    # Save new certificate
    with open(cert_path, "wb") as f:
        f.write(new_cert.public_bytes(encoding=Encoding.PEM))

    console.print(f"✅ Certificate renewed successfully for [bold]{hostname}[/bold]")
    console.print(f"  Certificate: [bold]{cert_path}[/bold]")

    # Deploy certificate if destination specified
    if "destination" in host_config and host_config["destination"]:
        dest_path = Path(host_config["destination"])

        # Ensure parent directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy certificate to destination
        try:
            with open(cert_path, "rb") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())
            console.print(f"✅ Certificate deployed to [bold]{dest_path}[/bold]")
        except Exception as e:
            console.print(f"[bold red]Error deploying certificate:[/bold red] {str(e)}")

    # Update inventory
    inventory = load_inventory()

    # Update host entry
    for host in inventory.get("hosts", []):
        if host["name"] == hostname:
            host["serial"] = format(new_cert.serial_number, "x")
            host["not_after"] = new_cert.not_valid_after.isoformat()
            host["fingerprint"] = "SHA256:" + new_cert.fingerprint(hashes.SHA256()).hex()
            host["renewal_count"] = host.get("renewal_count", 0) + 1
            break
    else:
        # Add new entry if not found
        inventory.setdefault("hosts", []).append({
            "name": hostname,
            "serial": format(new_cert.serial_number, "x"),
            "not_after": new_cert.not_valid_after.isoformat(),
            "fingerprint": "SHA256:" + new_cert.fingerprint(hashes.SHA256()).hex(),
            "renewal_count": 1,
        })

    inventory["last_update"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")


def renew_all_certificates():
    """Renew all certificates."""
    # Get list of all host directories
    hosts_dir = Path("certs/hosts")
    if not hosts_dir.exists():
        console.print("[bold yellow]Warning:[/bold yellow] No hosts directory found")
        return

    host_dirs = [d for d in hosts_dir.iterdir() if d.is_dir()]
    if not host_dirs:
        console.print("[bold yellow]Warning:[/bold yellow] No host certificates found")
        return

    # Renew each certificate
    success_count = 0
    error_count = 0

    for host_dir in host_dirs:
        hostname = host_dir.name
        console.print(f"\nRenewing certificate for [bold]{hostname}[/bold]...")

        try:
            renew_certificate(hostname)
            success_count += 1
        except Exception as e:
            console.print(f"[bold red]Error renewing {hostname}:[/bold red] {str(e)}")
            error_count += 1

    console.print(f"\n✅ Renewed {success_count} certificates successfully")
    if error_count > 0:
        console.print(f"❌ Failed to renew {error_count} certificates")


def list_certificates():
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

    ca_table = Table(title="CA Certificate")
    ca_table.add_column("Serial")
    ca_table.add_column("Expiration Date")
    ca_table.add_column("Fingerprint")

    ca_table.add_row(
        ca_info.get("serial", "Unknown"),
        ca_info.get("not_after", "Unknown"),
        ca_info.get("fingerprint", "Unknown"),
    )

    console.print(ca_table)

    # Display host certificates
    hosts = inventory.get("hosts", [])
    if not hosts:
        console.print("\nNo host certificates found")
        return

    host_table = Table(title="Host Certificates")
    host_table.add_column("Hostname")
    host_table.add_column("Serial")
    host_table.add_column("Expiration Date")
    host_table.add_column("Fingerprint")
    host_table.add_column("Renewals")

    # Calculate days remaining for each certificate
    now = datetime.datetime.now(datetime.timezone.utc)

    for host in hosts:
        name = host.get("name", "Unknown")
        serial = host.get("serial", "Unknown")
        not_after = host.get("not_after", "Unknown")
        fingerprint = host.get("fingerprint", "Unknown")
        renewal_count = str(host.get("renewal_count", 0))

        # Calculate days remaining
        days_remaining = "Unknown"
        if not_after != "Unknown":
            try:
                expiry_date = datetime.datetime.fromisoformat(not_after)
                delta = expiry_date - now
                days_remaining = delta.days

                # Format expiration date with color based on how soon it expires
                if days_remaining < 0:
                    not_after = f"[bold red]{not_after} (expired)[/bold red]"
                elif days_remaining < 30:
                    not_after = f"[bold orange]{not_after} ({days_remaining} days)[/bold orange]"
                elif days_remaining < 90:
                    not_after = f"[bold yellow]{not_after} ({days_remaining} days)[/bold yellow]"
                else:
                    not_after = f"{not_after} ({days_remaining} days)"
            except (ValueError, TypeError):
                pass

        host_table.add_row(name, serial, not_after, fingerprint, renewal_count)

    console.print("\n")
    console.print(host_table)

    # Show last update time
    last_update = inventory.get("last_update", "Unknown")
    console.print(f"\nLast updated: {last_update}")


def process_csr_file(csr_file_path):
    """Process a CSR file and generate a certificate."""
    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return

    csr_path = Path(csr_file_path)
    if not csr_path.exists():
        console.print(f"[bold red]Error:[/bold red] CSR file not found: {csr_file_path}")
        return

    # Load hosts config
    hosts_config = load_hosts_config()

    # Process the CSR
    hostname, cert = process_csr(csr_path, ca_key, ca_cert)
    if not hostname or not cert:
        return

    # Find host config if available
    host_config = None
    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    # Get validity period from host config if available
    if host_config:
        host_config.get("validity_days", 365)  # Not used but we check for completeness

    # Create host directory if it doesn't exist
    host_dir = Path(f"certs/hosts/{hostname}")
    host_dir.mkdir(parents=True, exist_ok=True)

    # Save certificate
    cert_path = host_dir / "cert.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

    console.print(f"✅ Certificate generated successfully for [bold]{hostname}[/bold]")
    console.print(f"  Certificate: [bold]{cert_path}[/bold]")

    # Deploy certificate if destination specified
    if host_config and "destination" in host_config and host_config["destination"]:
        dest_path = Path(host_config["destination"])

        # Ensure parent directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy certificate to destination
        try:
            with open(cert_path, "rb") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())
            console.print(f"✅ Certificate deployed to [bold]{dest_path}[/bold]")
        except Exception as e:
            console.print(f"[bold red]Error deploying certificate:[/bold red] {str(e)}")

    # Update inventory
    update_inventory()
    console.print("📋 Inventory updated")
