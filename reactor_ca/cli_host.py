"""Host certificate operations for ReactorCA.

This module provides high-level functions for managing host certificates
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reactor_ca import models

from click import Context
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from rich.table import Table

from reactor_ca.defaults import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS
from reactor_ca.export_deploy import (
    deploy as run_deploy_command,
)
from reactor_ca.export_deploy import (
    export_cert as export_host_cert,
)
from reactor_ca.export_deploy import (
    export_cert_chain as export_host_chain,
)
from reactor_ca.export_deploy import (
    export_unencrypted_key,
)
from reactor_ca.models import (
    CA,
    AlternativeNames,
    CertificateParams,
    SubjectIdentity,
)
from reactor_ca.password import get_password
from reactor_ca.paths import get_host_cert_path, get_host_key_path
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import (
    delete_host,
    host_exists,
    list_hosts as store_list_hosts,
    read_ca_cert,
    read_ca_key,
    read_host_cert,
    read_host_key,
    write_host_cert,
    write_host_key,
)
from reactor_ca.x509_crypto import (
    create_certificate,
    deserialize_certificate,
    deserialize_private_key,
    ensure_key_algorithm,
    generate_key,
    serialize_unencrypted_private_key,
)


def issue_certificate(
    ctx: Context,
    hostname: str,
    config: "models.Config",
    store: "models.Store",
    password: str,
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Issue or renew a certificate for a host.

    Args:
    ----
        ctx: Click context
        hostname: Hostname for the certificate
        config: Config object with loaded configurations
        store: Store object for path info
        password: The master password for decryption/encryption.
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]

    hosts_config = config.hosts_config
    if hosts_config is None or hostname not in hosts_config:
        return Failure(f"Host '{hostname}' not found in hosts configuration")
    host_config = hosts_config[hostname]

    # Load CA certificate and key
    ca_cert_res = read_ca_cert(store)
    if isinstance(ca_cert_res, Failure):
        return Failure(f"Failed to load CA certificate: {ca_cert_res.error}")
    ca_cert = ca_cert_res.unwrap()

    ca_key_res = read_ca_key(store, password)
    if isinstance(ca_key_res, Failure):
        return Failure(f"Failed to load CA key: {ca_key_res.error}")
    ca_key = ca_key_res.unwrap()

    # Handle host key creation or loading
    key_algorithm = host_config.key_algorithm
    is_new = not host_exists(store, hostname)
    private_key = None

    if is_new:
        console.print(f"Generating {key_algorithm.value} key for {hostname}...")
        key_result = generate_key(key_algorithm)
        if isinstance(key_result, Failure):
            return key_result
        private_key = key_result.unwrap()
    else:
        key_result = read_host_key(store, hostname, password)
        if isinstance(key_result, Failure):
            return Failure(f"Failed to load host key: {key_result.error}")
        private_key = key_result.unwrap()
        key_algo_res = ensure_key_algorithm(private_key, key_algorithm)
        if isinstance(key_algo_res, Failure):
            return Failure(f"Key algorithm mismatch for {hostname}. Use 'rekey' to change algorithm.")

    # Create CA object and certificate parameters
    if config.ca_config is None:
        return Failure("CA configuration is not loaded")
    ca_obj = CA(ca_config=config.ca_config, cert=ca_cert, key=ca_key)

    cert_params_res = CertificateParams.from_host_config(host_config=host_config, ca=ca_obj, private_key=private_key)
    if isinstance(cert_params_res, Failure):
        return cert_params_res
    cert_params = cert_params_res.unwrap()

    # Create and save certificate
    cert_res = create_certificate(cert_params)
    if isinstance(cert_res, Failure):
        return Failure(f"Failed to create certificate: {cert_res.error}")
    cert = cert_res.unwrap()

    if isinstance(write_host_cert(store, hostname, cert), Failure):
        return Failure(f"Failed to save host certificate for {hostname}")
    if is_new and isinstance(write_host_key(store, hostname, private_key, password), Failure):
        return Failure(f"Failed to save host key for {hostname}")

    # Export and Deploy
    if not no_export:
        _export_certificate(console, host_config, cert, ca_cert)
    if do_deploy:
        deploy_res = _deploy_certificate(console, store, password, host_config, cert, private_key)
        if isinstance(deploy_res, Failure):
            return deploy_res

    action = "created" if is_new else "renewed"
    console.print(f"✅ Certificate {action} successfully for [bold]{hostname}[/bold]")
    console.print(f"   Certificate: [bold]{get_host_cert_path(store, hostname)}[/bold]")
    if is_new:
        console.print(f"   Private key (encrypted): [bold]{get_host_key_path(store, hostname)}[/bold]")

    return Success(None)


def issue_all_certificates(
    ctx: Context,
    config: "models.Config",
    store: "models.Store",
    password: str,
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Issue or renew certificates for all hosts in configuration."""
    console = ctx.obj["console"]

    hosts_config = config.hosts_config
    if not hosts_config:
        return Failure("No hosts found in configuration")

    success_count, error_count = 0, 0
    for hostname in hosts_config:
        console.print(f"\nProcessing host: [bold]{hostname}[/bold]")
        cert_result = issue_certificate(ctx, hostname, config, store, password, no_export, do_deploy)
        if isinstance(cert_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {cert_result.error}")

    console.print(f"\n✅ Successfully processed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to process {error_count} certificates")

    return Success(None)


def rekey_host(
    ctx: Context,
    host_id: str,
    config: "models.Config",
    store: "models.Store",
    password: str,
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Generate a new key and certificate for a host."""
    console = ctx.obj["console"]

    hosts_config = config.hosts_config
    if not hosts_config or host_id not in hosts_config:
        return Failure(f"Host '{host_id}' not found in configuration")
    host_config = hosts_config[host_id]

    # Load CA certificate and key
    ca_cert_res = read_ca_cert(store)
    if isinstance(ca_cert_res, Failure):
        return ca_cert_res
    ca_cert = ca_cert_res.unwrap()
    ca_key_res = read_ca_key(store, password)
    if isinstance(ca_key_res, Failure):
        return ca_key_res
    ca_key = ca_key_res.unwrap()

    # Create new key
    console.print(f"Generating new {host_config.key_algorithm.value} key for {host_id}...")
    key_result = generate_key(host_config.key_algorithm)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to generate key: {key_result.error}")
    private_key = key_result.unwrap()

    if config.ca_config is None:
        return Failure("CA configuration is not loaded")
    ca_obj = CA(ca_config=config.ca_config, cert=ca_cert, key=ca_key)

    cert_params_res = CertificateParams.from_host_config(host_config=host_config, ca=ca_obj, private_key=private_key)
    if isinstance(cert_params_res, Failure):
        return cert_params_res

    cert_res = create_certificate(cert_params_res.unwrap())
    if isinstance(cert_res, Failure):
        return Failure(f"Failed to create certificate: {cert_res.error}")
    cert = cert_res.unwrap()

    # Save new key and cert
    write_host_cert(store, host_id, cert)
    write_host_key(store, host_id, private_key, password)

    # Export and Deploy
    if not no_export:
        _export_certificate(console, host_config, cert, ca_cert)
    if do_deploy:
        deploy_res = _deploy_certificate(console, store, password, host_config, cert, private_key)
        if isinstance(deploy_res, Failure):
            return deploy_res

    console.print(f"✅ Certificate and key rekeyed successfully for [bold]{host_id}[/bold]")
    return Success(None)


def rekey_all_hosts(
    ctx: Context,
    config: "models.Config",
    store: "models.Store",
    password: str,
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Rekey all hosts in configuration."""
    console = ctx.obj["console"]
    hosts_config = config.hosts_config
    if not hosts_config:
        return Failure("No hosts found in configuration")

    success_count, error_count = 0, 0
    for host_id in hosts_config:
        console.print(f"\nRekeying host: [bold]{host_id}[/bold]")
        rekey_result = rekey_host(ctx, host_id, config, store, password, no_export, do_deploy)
        if isinstance(rekey_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {rekey_result.error}")

    console.print(f"\n✅ Successfully rekeyed {success_count} hosts")
    if error_count > 0:
        console.print(f"❌ Failed to rekey {error_count} hosts")

    return Success(None)


def import_host_key(
    ctx: Context, host_id: str, key_path: Path, config: "models.Config", store: "models.Store", password: str
) -> Result[None, str]:
    """Import an existing private key for a host."""
    console = ctx.obj["console"]
    if host_exists(store, host_id):
        return Failure(f"Key for {host_id} already exists. Remove it first.")

    try:
        key_data = key_path.read_bytes()
        # Prompt for source key password
        src_password_res = get_password(min_length=1, prompt_message="Enter password for key to import (or press Enter if none): ", confirm=False)
        src_password = src_password_res.unwrap() if isinstance(src_password_res, Success) else None

        private_key_res = deserialize_private_key(key_data, src_password)
        if isinstance(private_key_res, Failure):
            return Failure(f"Failed to load private key: {private_key_res.error}")
        private_key = private_key_res.unwrap()

        key_save_res = write_host_key(store, host_id, private_key, password)
        if isinstance(key_save_res, Failure):
            return Failure(f"Failed to save imported host key: {key_save_res.error}")

        console.print(f"✅ Key imported successfully for [bold]{host_id}[/bold]")
        return Success(None)
    except Exception as e:
        return Failure(f"Error loading key file: {e!s}")


def export_host_key_unencrypted_wrapper(
    ctx: Context, host_id: str, store: "models.Store", password: str, out_path: str | None = None
) -> Result[None, str]:
    """Export an unencrypted private key for a host."""
    console = ctx.obj["console"]
    key_result = read_host_key(store, host_id, password)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load host key: {key_result.error}")
    private_key = key_result.unwrap()

    if out_path:
        export_result = export_unencrypted_key(private_key, Path(out_path))
        if isinstance(export_result, Failure):
            return Failure(f"Failed to export unencrypted key: {export_result.error}")
        console.print(f"✅ Unencrypted key exported to [bold]{out_path}[/bold]")
    else:
        key_bytes_res = serialize_unencrypted_private_key(private_key)
        if isinstance(key_bytes_res, Failure):
            return key_bytes_res
        console.print(key_bytes_res.unwrap().decode("utf-8"))

    return Success(None)


def deploy_host(
    ctx: Context, host_id: str, config: "models.Config", store: "models.Store", password: str
) -> Result[None, str]:
    """Run the deployment script for a host."""
    console = ctx.obj["console"]
    hosts_config = config.hosts_config
    if not hosts_config or host_id not in hosts_config:
        return Failure(f"Host '{host_id}' not found in configuration")
    host_config = hosts_config[host_id]

    if not host_config.deploy or not host_config.deploy.command:
        return Failure(f"No deployment command configured for host {host_id}")

    # Load host cert and key for deployment
    cert_res = read_host_cert(store, host_id)
    if isinstance(cert_res, Failure):
        return cert_res
    key_res = read_host_key(store, host_id, password)
    if isinstance(key_res, Failure):
        return key_res

    deploy_result = _deploy_certificate(console, store, password, host_config, cert_res.unwrap(), key_res.unwrap())
    if isinstance(deploy_result, Failure):
        return deploy_result

    console.print(f"✅ Deployment completed successfully for [bold]{host_id}[/bold]")
    return Success(None)


def deploy_all_hosts(ctx: Context, config: "models.Config", store: "models.Store", password: str) -> Result[None, str]:
    """Deploy all host certificates."""
    console = ctx.obj["console"]
    hosts_config = config.hosts_config
    if not hosts_config:
        return Failure("No hosts found in configuration")

    success_count, error_count = 0, 0
    for host_id in hosts_config:
        host_config = hosts_config[host_id]
        if not host_config.deploy or not host_config.deploy.command:
            console.print(f"[yellow]Skipping deployment for {host_id}: no command configured[/yellow]")
            continue

        console.print(f"\nDeploying host: [bold]{host_id}[/bold]")
        deploy_result = deploy_host(ctx, host_id, config, store, password)
        if isinstance(deploy_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {deploy_result.error}")

    console.print(f"\n✅ Successfully deployed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to deploy {error_count} certificates")

    return Success(None)


def get_certificates_list_dict(
    store: "models.Store", expired: bool = False, expiring_days: int | None = None
) -> Result[dict[str, Any], str]:
    """Get a dictionary with certificate list information."""
    ca_cert_res = read_ca_cert(store)
    if isinstance(ca_cert_res, Failure):
        return ca_cert_res
    ca_cert = ca_cert_res.unwrap()

    now = datetime.datetime.now(datetime.UTC)
    ca_info = {
        "serial": format(ca_cert.serial_number, "x"),
        "not_after": ca_cert.not_valid_after_utc.isoformat(),
        "days_remaining": (ca_cert.not_valid_after_utc - now).days,
    }

    hosts_list_res = store_list_hosts(store)
    if isinstance(hosts_list_res, Failure):
        return hosts_list_res

    filtered_hosts = []
    for host_id in hosts_list_res.unwrap():
        cert_res = read_host_cert(store, host_id)
        if isinstance(cert_res, Failure):
            continue  # Skip hosts with certificate read errors
        cert = cert_res.unwrap()

        days_remaining = (cert.not_valid_after_utc - now).days
        if (expired and days_remaining >= 0) or (expiring_days is not None and days_remaining > expiring_days):
            continue

        host_info = {
            "host_id": host_id,
            "serial": format(cert.serial_number, "x"),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "days_remaining": days_remaining,
            "fingerprint": f"SHA256:{cert.fingerprint(hashes.SHA256()).hex()}",
        }
        filtered_hosts.append(host_info)

    return Success(
        {
            "ca": ca_info,
            "hosts": filtered_hosts,
            "total": len(filtered_hosts),
            "filters": {"expired": expired, "expiring_days": expiring_days},
        }
    )


def _format_expiry_days(days: int) -> str:
    """Format days remaining with color."""
    if days < 0:
        return f"[bold red]{days} (expired)[/bold red]"
    if days < EXPIRY_CRITICAL_DAYS:
        return f"[bold red]{days}[/bold red]"
    if days < EXPIRY_WARNING_DAYS:
        return f"[bold yellow]{days}[/bold yellow]"
    return str(days)


def list_certificates(
    ctx: Context, store: "models.Store", expired: bool = False, expiring_days: int | None = None
) -> Result[None, str]:
    """List certificates with their expiration dates."""
    console = ctx.obj["console"]
    result = get_certificates_list_dict(store, expired, expiring_days)
    if isinstance(result, Failure):
        return result
    data = result.unwrap()

    ca_table = Table(title="CA Certificate")
    ca_table.add_column("Serial")
    ca_table.add_column("Expiration Date")
    ca_table.add_column("Days Remaining")
    ca_table.add_row(data["ca"]["serial"], data["ca"]["not_after"], _format_expiry_days(data["ca"]["days_remaining"]))
    console.print(ca_table)

    if not data["hosts"]:
        console.print("\nNo host certificates match the criteria.")
        return Success(None)

    host_table = Table(title="Host Certificates", show_header=True)
    host_table.add_column("Host ID")
    host_table.add_column("Serial")
    host_table.add_column("Expiration Date")
    host_table.add_column("Days Remaining")
    host_table.add_column("Fingerprint")
    for host in sorted(data["hosts"], key=lambda x: x["host_id"]):
        host_table.add_row(
            host["host_id"],
            host["serial"],
            host["not_after"],
            _format_expiry_days(host["days_remaining"]),
            host["fingerprint"],
        )
    console.print("\n")
    console.print(host_table)
    return Success(None)


def clean_certificates(ctx: Context, config: "models.Config", store: "models.Store") -> Result[None, str]:
    """Remove host folders that are no longer in the configuration."""
    console = ctx.obj["console"]
    configured_hosts = list(config.hosts_config.keys()) if config.hosts_config else []
    existing_hosts_res = store_list_hosts(store)
    if isinstance(existing_hosts_res, Failure):
        return existing_hosts_res
    hosts_to_remove = [host for host in existing_hosts_res.unwrap() if host not in configured_hosts]

    if not hosts_to_remove:
        console.print("✅ No unconfigured host folders found.")
        return Success(None)

    removed_count = 0
    for host_id in hosts_to_remove:
        delete_result = delete_host(store, host_id)
        if isinstance(delete_result, Success):
            console.print(f"✅ Removed host folder for [bold]{host_id}[/bold]")
            removed_count += 1
        else:
            console.print(f"[bold red]Error:[/bold red] Failed to remove {host_id}: {delete_result.error}")

    if removed_count > 0:
        console.print(f"\n✅ Removed {removed_count} unconfigured host folder(s).")
    return Success(None)


def get_host_info(hostname: str, store: "models.Store") -> Result[dict[str, Any], str]:
    """Get detailed information about a host certificate."""
    cert_res = read_host_cert(store, hostname)
    if isinstance(cert_res, Failure):
        return Failure(f"Failed to load certificate for '{hostname}': {cert_res.error}")
    cert = cert_res.unwrap()

    now = datetime.datetime.now(datetime.UTC)
    host_info = {
        "host_id": hostname,
        "serial": format(cert.serial_number, "x"),
        "subject": {attr.oid._name: attr.value for attr in cert.subject},
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_remaining": (cert.not_valid_after_utc - now).days,
        "fingerprint": f"SHA256:{cert.fingerprint(hashes.SHA256()).hex()}",
    }
    return Success(host_info)


def process_csr(
    ctx: Context,
    csr_path_str: str,
    config: "models.Config",
    store: "models.Store",
    password: str,
    validity_days: int = 365,
    out_path: str | None = None,
) -> Result[None, str]:
    """Process a Certificate Signing Request."""
    console = ctx.obj["console"]
    try:
        csr_data = Path(csr_path_str).read_bytes()
        csr = x509.load_pem_x509_csr(csr_data)
    except Exception as e:
        return Failure(f"Failed to load CSR: {e!s}")

    if not csr.is_signature_valid:
        return Failure("CSR has an invalid signature")

    hostname_attrs = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not hostname_attrs:
        return Failure("Could not extract hostname from CSR (missing Common Name)")
    hostname = hostname_attrs[0].value

    ca_cert_res = read_ca_cert(store)
    if isinstance(ca_cert_res, Failure):
        return ca_cert_res
    ca_key_res = read_ca_key(store, password)
    if isinstance(ca_key_res, Failure):
        return ca_key_res

    if config.ca_config is None:
        return Failure("CA configuration is not loaded")
    ca_obj = CA(ca_config=config.ca_config, cert=ca_cert_res.unwrap(), key=ca_key_res.unwrap())

    # Build params from CSR
    subject_identity = SubjectIdentity.from_x509_name(csr.subject).unwrap()
    alt_names = AlternativeNames.from_extensions(csr.extensions)
    cert_params = CertificateParams(
        subject_identity=subject_identity,
        ca=ca_obj,
        private_key=None,  # Not needed, public key is in CSR
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=config.ca_config.hash_algorithm,
    )

    cert_res = create_certificate(cert_params, public_key=csr.public_key())
    if isinstance(cert_res, Failure):
        return Failure(f"Failed to create certificate from CSR: {cert_res.error}")
    cert = cert_res.unwrap()

    if out_path:
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(cert.public_bytes(x509.serialization.Encoding.PEM))

    console.print(f"✅ Successfully signed CSR for [bold]{hostname}[/bold]")
    if out_path:
        console.print(f"   Certificate saved to: [bold]{out_path}[/bold]")
    return Success(None)


# --- Private Helper Functions ---


def _export_certificate(
    console: Any, host_config: "models.HostConfig", cert: x509.Certificate, ca_cert: x509.Certificate
) -> None:
    """Handle the certificate export logic."""
    if host_config.export:
        if host_config.export.cert:
            export_host_cert(cert, Path(host_config.export.cert))
        if host_config.export.chain:
            export_host_chain(cert, ca_cert, Path(host_config.export.chain))


def _deploy_certificate(
    console: Any,
    store: "models.Store",
    password: str,
    host_config: "models.HostConfig",
    cert: x509.Certificate,
    private_key: "models.PrivateKeyTypes",
) -> Result[None, str]:
    """Handle the certificate deployment logic."""
    if not host_config.deploy or not host_config.deploy.command:
        return Success(None)

    console.print(f"Deploying certificate for [bold]{host_config.host_id}[/bold]...")
    key_res = read_host_key(store, host_config.host_id, password)
    if isinstance(key_res, Failure):
        return Failure(f"Failed to load host key for deployment: {key_res.error}")

    deploy_result = run_deploy_command(host_config.deploy.command, cert, private_key)
    if isinstance(deploy_result, Success):
        console.print("✅ Deployment command executed successfully")
        return Success(None)
    return Failure(f"Deployment failed: {deploy_result.error}")
