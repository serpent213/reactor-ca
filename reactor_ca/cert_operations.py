"""Certificate operations for ReactorCA."""

import datetime
import ipaddress
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.table import Table

from reactor_ca.ca_operations import (
    decrypt_key,
    encrypt_key,
    generate_key,
)
from reactor_ca.utils import (
    calculate_validity_days,
    get_password,
    load_config,
    load_hosts_config,
    load_inventory,
    run_deploy_command,
    save_inventory,
    update_inventory,
)
from reactor_ca.config_validator import validate_config_before_operation

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


def export_certificate(hostname, certificate, key=None, chain=True, no_export=False):
    """Export a certificate and optionally its private key and chain to the configured location."""
    if no_export:
        console.print(f"Certificate export skipped for [bold]{hostname}[/bold] (--no-export flag)")
        return False

    hosts_config = load_hosts_config()
    host_config = None

    for host in hosts_config.get("hosts", []):
        if host["name"] == hostname:
            host_config = host
            break

    if not host_config:
        console.print(f"[bold yellow]Warning:[/bold yellow] Host {hostname} not found in hosts configuration")
        return False

    # Get export paths from config
    if "export" not in host_config:
        console.print(f"[bold yellow]Warning:[/bold yellow] No export paths configured for {hostname}")
        return False

    export_config = host_config["export"]
    cert_path = export_config.get("cert")
    chain_path = export_config.get("chain")

    if not cert_path:
        console.print(f"[bold yellow]Warning:[/bold yellow] No certificate export path configured for {hostname}")
        return False

    export_success = False

    # Ensure parent directories exist
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
        ca_cert_path = Path("certs/ca/ca.crt")
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

    return export_success


def deploy_host(hostname):
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


def process_csr(csr_path, ca_key, ca_cert, validity_days=365, out_path=None):
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
                hostname = attr.value
                break

        if not hostname:
            console.print("[bold red]Error:[/bold red] Could not extract hostname from CSR")
            return None, None

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

        # Save the certificate if an output path is provided
        if out_path:
            out_path = Path(out_path)
            with open(out_path, "wb") as f:
                f.write(cert.public_bytes(encoding=Encoding.PEM))
            console.print(f"✅ Certificate saved to [bold]{out_path}[/bold]")

        return hostname, cert

    except Exception as e:
        console.print(f"[bold red]Error processing CSR:[/bold red] {str(e)}")
        return None, None


def issue_certificate(hostname, no_export=False, do_deploy=False):
    """Issue or renew a certificate for a host."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print("[bold red]Error:[/bold red] Configuration validation failed. Please correct the configuration before issuing certificates.")
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

    # Check if certificate and key exist
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_path = host_dir / "cert.key.enc"

    is_new = False

    if not cert_path.exists() or not key_path.exists():
        # This is a new certificate
        is_new = True
        host_dir.mkdir(parents=True, exist_ok=True)

        # Generate key
        key_algo = host_config.get("key", {}).get("algorithm", "RSA")
        key_size = host_config.get("key", {}).get("size", 2048)

        console.print(f"Generating {key_algo} key for {hostname}...")
        private_key = generate_key(algorithm=key_algo, size=key_size)

        # Get password for key encryption
        password = get_password()
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

    # Get validity period
    validity_days = calculate_validity_days(host_config.get("validity", {"days": 365}))

    # Get alternative names
    alt_names = host_config.get("alternative_names", {})

    action = "Generating" if is_new else "Renewing"
    console.print(f"{action} certificate for {hostname} valid for {validity_days} days...")

    # Create certificate
    cert = create_certificate(
        private_key,
        hostname,
        ca_key,
        ca_cert,
        validity_days,
        alt_names,
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
    export_success = export_certificate(hostname, cert, no_export=no_export)

    # Deploy if requested and export was successful
    if do_deploy and export_success:
        deploy_host(hostname)

    # Update inventory
    inventory = load_inventory()

    # Update or add host entry
    for host in inventory.setdefault("hosts", []):
        if host["name"] == hostname:
            host["serial"] = format(cert.serial_number, "x")
            host["not_after"] = cert.not_valid_after.isoformat()
            host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
            host["renewal_count"] = host.get("renewal_count", 0) + 1
            break
    else:
        # Add new entry if not found
        inventory.setdefault("hosts", []).append({
            "name": hostname,
            "serial": format(cert.serial_number, "x"),
            "not_after": cert.not_valid_after.isoformat(),
            "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
            "renewal_count": 1,
        })

    inventory["last_update"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def issue_all_certificates(no_export=False, do_deploy=False):
    """Issue or renew certificates for all hosts in configuration."""
    # Validate configuration first
    if not validate_config_before_operation():
        console.print("[bold red]Error:[/bold red] Configuration validation failed. Please correct the configuration before issuing certificates.")
        return False
        
    hosts_config = load_hosts_config()

    hosts = [host["name"] for host in hosts_config.get("hosts", [])]
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


def rekey_host(hostname, no_export=False, do_deploy=False):
    """Generate a new key and certificate for a host."""
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

    # Create host directory if it doesn't exist
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_path = host_dir / "cert.key.enc"

    # Create directory if needed
    host_dir.mkdir(parents=True, exist_ok=True)


    # Generate new key
    key_algo = host_config.get("key", {}).get("algorithm", "RSA")
    key_size = host_config.get("key", {}).get("size", 2048)

    console.print(f"Generating new {key_algo} key for {hostname}...")
    private_key = generate_key(algorithm=key_algo, size=key_size)

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
    export_success = export_certificate(hostname, cert, no_export=no_export)

    # Deploy if requested and export was successful
    if do_deploy and export_success:
        deploy_host(hostname)

    # Update inventory
    inventory = load_inventory()

    # Update or add host entry
    for host in inventory.setdefault("hosts", []):
        if host["name"] == hostname:
            host["serial"] = format(cert.serial_number, "x")
            host["not_after"] = cert.not_valid_after.isoformat()
            host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
            host["renewal_count"] = host.get("renewal_count", 0) + 1
            host["rekeyed"] = True
            break
    else:
        # Add new entry if not found
        inventory.setdefault("hosts", []).append({
            "name": hostname,
            "serial": format(cert.serial_number, "x"),
            "not_after": cert.not_valid_after.isoformat(),
            "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
            "renewal_count": 1,
            "rekeyed": True,
        })

    inventory["last_update"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_inventory(inventory)
    console.print("📋 Inventory updated")

    return True


def rekey_all_hosts(no_export=False, do_deploy=False):
    """Rekey all hosts in configuration."""
    hosts_config = load_hosts_config()

    hosts = [host["name"] for host in hosts_config.get("hosts", [])]
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


def import_host_key(hostname, key_path):
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

    # Check if host certificate already exists
    host_dir = Path(f"certs/hosts/{hostname}")
    cert_path = host_dir / "cert.crt"
    key_dest_path = host_dir / "cert.key.enc"

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
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            private_key = load_pem_private_key(key_data, password=None)
            src_password = None
        except (TypeError, ValueError):
            # If that fails, prompt for the source key password
            src_password = click.prompt(
                "Enter source key password", hide_input=True, default="", show_default=False
            )
            try:
                private_key = load_pem_private_key(key_data, password=src_password.encode() if src_password else None)
            except Exception as e:
                console.print(f"[bold red]Error decrypting source key:[/bold red] {str(e)}")
                return False
    except Exception as e:
        console.print(f"[bold red]Error loading key:[/bold red] {str(e)}")
        return False

    # Get password for encrypting the key
    dest_password = get_password()
    if not dest_password:
        return False

    # Encrypt and save the key
    with open(key_dest_path, "wb") as f:
        f.write(encrypt_key(private_key, dest_password))

    console.print(f"✅ Key imported successfully for [bold]{hostname}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{key_dest_path}[/bold]")

    return True


def export_host_key(hostname, out_path=None):
    """Export an unencrypted private key for a host."""
    # Check if host key exists
    host_dir = Path(f"certs/hosts/{hostname}")
    key_path = host_dir / "cert.key.enc"

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
    unencrypted_key_data = private_key.private_bytes(
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
        console.print(unencrypted_key_data.decode('utf-8'))

    return True


def list_certificates(expired=False, expiring_days=None, json_output=False):
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
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_days_remaining = None

    if "not_after" in ca_info:
        try:
            ca_expiry_date = datetime.datetime.fromisoformat(ca_info["not_after"])
            ca_expiry_date = ca_expiry_date.replace(tzinfo=datetime.timezone.utc)
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
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
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
        else:
            # Include hosts with unknown expiry if not filtering
            if not expired and expiring_days is None:
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
        if ca_days_remaining < 0:
            days_formatted = f"[bold red]{ca_days_remaining} (expired)[/bold red]"
        elif ca_days_remaining < 30:
            days_formatted = f"[bold orange]{ca_days_remaining}[/bold orange]"
        elif ca_days_remaining < 90:
            days_formatted = f"[bold yellow]{ca_days_remaining}[/bold yellow]"
        else:
            days_formatted = f"{ca_days_remaining}"

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

        # Format days remaining with color
        days_formatted = "Unknown"
        if days_remaining != "Unknown":
            if days_remaining < 0:
                days_formatted = f"[bold red]{days_remaining} (expired)[/bold red]"
            elif days_remaining < 30:
                days_formatted = f"[bold orange]{days_remaining}[/bold orange]"
            elif days_remaining < 90:
                days_formatted = f"[bold yellow]{days_remaining}[/bold yellow]"
            else:
                days_formatted = f"{days_remaining}"

        host_table.add_row(name, serial, not_after, days_formatted, fingerprint, renewal_count)

    console.print("\n")
    console.print(host_table)

    # Show last update time
    last_update = inventory.get("last_update", "Unknown")
    console.print(f"\nLast updated: {last_update}")


def deploy_all_hosts():
    """Deploy all host certificates."""
    hosts_config = load_hosts_config()

    hosts = [host["name"] for host in hosts_config.get("hosts", [])]
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
