"""Host certificate operations for ReactorCA.

This module provides high-level functions for managing host certificates
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reactor_ca import models

from click import Context
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.general_name import DirectoryName, UniformResourceIdentifier
from cryptography.x509.oid import NameOID
from rich.table import Table

from reactor_ca.export_deploy import deploy, export_cert, export_cert_chain, export_unencrypted_key
from reactor_ca.models import (
    CA,
    AlternativeNames,
    CAConfig,
    CertificateParams,
    HostConfig,
    SubjectIdentity,
    ValidityConfig,
)
from reactor_ca.password import get_password
from reactor_ca.paths import resolve_paths
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import delete_host, host_exists, read_host_cert, read_host_key, write_host_cert, write_host_key
from reactor_ca.store import list_hosts as store_list_hosts
from reactor_ca.x509_crypto import (
    create_certificate,
    deserialize_certificate,
    deserialize_private_key,
    generate_key,
)


def _load_configs(
    config: "models.Config",
) -> Result[tuple[CAConfig, dict[str, Any]], str]:
    """Get CA and hosts configurations from the Config object.

    Args:
    ----
        config: Config object with loaded configurations

    Returns:
    -------
        Result with tuple of (CAConfig, hosts_config) or error message

    """
    # Configurations are already loaded in the Config object
    return Success((config.ca_config, config.hosts_config))


def _get_password_from_store(store: "models.Store", config: "models.Config") -> Result[str, str]:
    """Get password from Store or prompt using config parameters.

    Args:
    ----
        store: Store object that might already be unlocked
        config: Config object with password configuration

    Returns:
    -------
        Result with password string or error message

    """
    # If store is already unlocked with a password, use it
    if store.unlocked and store.password:
        return Success(store.password)

    # Store is not unlocked, prompt for password using config settings
    password_result = get_password(
        min_length=config.ca_config.password.min_length,
        password_file=config.ca_config.password.file,
        env_var=config.ca_config.password.env_var,
        prompt_message="Enter CA master password: ",
        confirm=False,
    )

    if isinstance(password_result, Failure):
        return Failure(f"Failed to get password: {password_result.error}")

    password = password_result.unwrap()
    if password is None:
        return Failure("Password cannot be None")

    return Success(password)


def issue_certificate(
    ctx: Context,
    hostname: str,
    config: "models.Config",
    store: "models.Store",
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Issue or renew a certificate for a host.

    Args:
    ----
        ctx: Click context
        hostname: Hostname for the certificate
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get configurations from the Config object
    hosts_config = config.hosts_config
    
    # Find host config in the dictionary
    if hostname not in hosts_config:
        return Failure(f"Host {hostname} not found in hosts configuration")
    
    host_config = hosts_config[hostname]

    # Check if certificate and key exist
    key_algorithm = host_config.key_algorithm
    host_key_path = get_store_host_key_path(store, hostname)
    is_new = not host_key_path.exists()

    # Load the CA certificate
    cert_result = read_ca_cert(store)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {cert_result.error}")
    ca_cert = cert_result.unwrap()
    
    # Load the CA key
    key_result = read_ca_key(store)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load CA key: {key_result.error}")
    ca_key = key_result.unwrap()

    # Handle key creation or loading
    private_key = None

    if is_new:
        # Create new key
        console.print(f"Generating {key_algorithm.value} key for {hostname}...")
        key_result = generate_key(key_algorithm)
        if isinstance(key_result, Failure):
            return key_result
        private_key = key_result.unwrap()
    else:
        # Load existing key
        key_result = read_host_key(store, hostname)
        if isinstance(key_result, Failure):
            return Failure(f"Failed to load host key: {key_result.error}")
        private_key = key_result.unwrap()

        # Verify key algorithm
        key_algorithm_result = verify_key_algorithm(private_key, key_algorithm)
        if isinstance(key_algorithm_result, Failure):
            return Failure("Key algorithm mismatch. To use a new algorithm, please use rekey_host instead.")

    # Get validity period
    validity_days_result = host_config.validity.to_days()
    if isinstance(validity_days_result, Failure):
        return validity_days_result
    validity_days = validity_days_result.unwrap()

    # Create CA object
    ca_obj = CA(
        ca_config=config.ca_config,
        cert=ca_cert,
        key=ca_key,
    )

    # Create certificate parameters
    cert_params_result = CertificateParams.from_host_config(
        host_config=host_config, 
        ca=ca_obj,
        private_key=private_key
    )
    if isinstance(cert_params_result, Failure):
        return cert_params_result
    cert_params = cert_params_result.unwrap()

    # Create certificate
    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_save_result = write_host_cert(store, hostname, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    if is_new:
        key_save_result = write_host_key(store, hostname, private_key)
        if isinstance(key_save_result, Failure):
            return Failure(f"Failed to save host key: {key_save_result.error}")

    # Export certificate if requested
    if not no_export and host_config.export is not None:
        if host_config.export.cert is not None:
            cert_path = Path(host_config.export.cert)
            cert_export_result = export_host_cert(cert, cert_path)
            if isinstance(cert_export_result, Success):
                console.print(f"✅ Certificate exported to [bold]{cert_path}[/bold]")

        if host_config.export.chain is not None:
            chain_path = Path(host_config.export.chain)
            chain_export_result = export_host_chain(cert, ca_cert, chain_path)
            if isinstance(chain_export_result, Success):
                console.print(f"✅ Certificate chain exported to [bold]{chain_path}[/bold]")

    # Deploy if requested
    if do_deploy and host_config.deploy is not None:
        deploy_command = host_config.deploy.command
        if deploy_command:
            deploy_result = run_deploy_command(deploy_command, hostname)
            if isinstance(deploy_result, Success):
                console.print("✅ Deployment command executed successfully")

    # Print success message
    action = "created" if is_new else "renewed"
    console.print(f"✅ Certificate {action} successfully for [bold]{hostname}[/bold]")
    console.print(f"   Certificate: [bold]{get_store_host_cert_path(store, hostname)}[/bold]")
    if is_new:
        console.print(f"   Private key (encrypted): [bold]{get_store_host_key_path(store, hostname)}[/bold]")

    return Success(None)


def issue_all_certificates(
    ctx: Context,
    config: "models.Config",
    store: "models.Store",
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Issue or renew certificates for all hosts in configuration.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get hosts from configuration
    hosts_config = config.hosts_config
    hosts = list(hosts_config.keys())

    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0

    for hostname in hosts:
        console.print(f"\nProcessing host: [bold]{hostname}[/bold]")
        cert_result = issue_certificate(ctx, hostname, config, store, no_export, do_deploy)

        if isinstance(cert_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {cert_result.error if isinstance(cert_result, Failure) else 'Unknown error'}")

    # Print summary
    console.print(f"\n✅ Successfully processed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to process {error_count} certificates")

    return Success(None)


def rekey_host(
    ctx: Context,
    host_id: str,
    config: "models.Config",
    store: "models.Store",
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Generate a new key and certificate for a host.

    Args:
    ----
        ctx: Click context
        host_id: Host ID for the certificate
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get configurations from the Config object
    hosts_config = config.hosts_config
    
    # Find host config in the dictionary
    if host_id not in hosts_config:
        return Failure(f"Host {host_id} not found in hosts configuration")
    
    host_config = hosts_config[host_id]

    # Load the CA certificate
    cert_result = read_ca_cert(store)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {cert_result.error}")
    ca_cert = cert_result.unwrap()
    
    # Load the CA key
    key_result = read_ca_key(store)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load CA key: {key_result.error}")
    ca_key = key_result.unwrap()

    # Create new key
    key_algorithm = host_config.key_algorithm
    console.print(f"Generating {key_algorithm.value} key for {host_id}...")
    key_result = generate_key(key_algorithm)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to generate key: {key_result.error}")
    private_key = key_result.unwrap()

    # Get validity period
    validity_days_result = host_config.validity.to_days()
    if isinstance(validity_days_result, Failure):
        return validity_days_result
    validity_days = validity_days_result.unwrap()

    # Create CA object
    ca_obj = CA(
        ca_config=config.ca_config,
        cert=ca_cert,
        key=ca_key,
    )

    # Create certificate parameters
    cert_params_result = CertificateParams.from_host_config(
        host_config=host_config, 
        ca=ca_obj,
        private_key=private_key
    )
    if isinstance(cert_params_result, Failure):
        return cert_params_result
    cert_params = cert_params_result.unwrap()

    # Create certificate
    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_save_result = write_host_cert(store, host_id, cert)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    key_save_result = write_host_key(store, host_id, private_key)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save host key: {key_save_result.error}")

    # Export certificate if requested
    if not no_export and host_config.export is not None:
        if host_config.export.cert is not None:
            cert_path = Path(host_config.export.cert)
            cert_export_result = export_cert(cert, cert_path)
            if isinstance(cert_export_result, Success):
                console.print(f"✅ Certificate exported to [bold]{cert_path}[/bold]")

        if host_config.export.chain is not None:
            chain_path = Path(host_config.export.chain)
            chain_export_result = export_cert_chain(cert, ca_cert, chain_path)
            if isinstance(chain_export_result, Success):
                console.print(f"✅ Certificate chain exported to [bold]{chain_path}[/bold]")

    # Deploy if requested
    if do_deploy and host_config.deploy is not None:
        deploy_command = host_config.deploy.command
        if deploy_command:
            deploy_result = deploy(deploy_command, cert, private_key)
            if isinstance(deploy_result, Success):
                console.print("✅ Deployment command executed successfully")

    # Print success message
    console.print(f"✅ Certificate and key rekeyed successfully for [bold]{host_id}[/bold]")
    console.print(f"   Certificate: [bold]{get_store_host_cert_path(store, host_id)}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_store_host_key_path(store, host_id)}[/bold]")

    return Success(None)


def rekey_all_hosts(
    ctx: Context,
    config: "models.Config",
    store: "models.Store",
    no_export: bool = False,
    do_deploy: bool = False,
) -> Result[None, str]:
    """Rekey all hosts in configuration.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get hosts from configuration
    hosts_config = config.hosts_config
    host_ids = list(hosts_config.keys())

    if not host_ids:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0

    for host_id in host_ids:
        console.print(f"\nProcessing host: [bold]{host_id}[/bold]")
        rekey_result = rekey_host(ctx, host_id, config, store, no_export, do_deploy)

        if isinstance(rekey_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {rekey_result.error if isinstance(rekey_result, Failure) else 'Unknown error'}")

    # Print summary
    console.print(f"\n✅ Successfully rekeyed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to rekey {error_count} certificates")

    return Success(None)


def import_host_key(
    ctx: Context,
    host_id: str,
    key_path: str,
    config: "models.Config",
    store: "models.Store",
    src_password: str | None = None,
) -> Result[None, str]:
    """Import an existing private key for a host.

    Args:
    ----
        ctx: Click context
        host_id: Host ID for the key
        key_path: Path to the key file to import
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        src_password: Optional password for decrypting the source key

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Check if source key file exists
    src_key_path = Path(key_path)
    if not src_key_path.exists():
        return Failure(f"Key file not found: {key_path}")

    # Check if host already has a key
    if host_exists(store, host_id):
        return Failure(
            f"Certificate or key for {host_id} already exists. Remove it first or use a different host ID."
        )

    # Load the key
    try:
        with open(src_key_path, "rb") as f:
            key_data = f.read()

        # Try to load it without password first
        private_key_result = deserialize_private_key(key_data, None)
        if isinstance(private_key_result, Failure):
            # If deserialization fails, assume it's password-protected
            if src_password:
                private_key_result = deserialize_private_key(key_data, src_password.encode())
                if isinstance(private_key_result, Failure):
                    return Failure(f"Failed to decrypt key with provided password: {private_key_result.error}")
            else:
                # Prompt for password
                src_password_result = get_password(
                    min_length=4,  # Lower minimum for source key (we don't know the requirements)
                    prompt_message="Enter password for key to import: ",
                    confirm=False,
                )
                if isinstance(src_password_result, Failure):
                    return Failure(f"Failed to get source key password: {src_password_result.error}")
                src_password = src_password_result.unwrap()

                # Make sure password is not None before encoding
                if src_password is None:
                    return Failure("Source password cannot be None")

                private_key_result = deserialize_private_key(key_data, src_password.encode())
                if isinstance(private_key_result, Failure):
                    return Failure(f"Failed to deserialize private key: {private_key_result.error}")
    except Exception as e:
        return Failure(f"Error loading key file: {str(e)}")

    private_key = private_key_result.unwrap()

    # Save the key to the store
    key_save_result = write_host_key(store, host_id, private_key)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save host key: {key_save_result.error}")

    # Print success message
    console.print(f"✅ Key imported successfully for [bold]{host_id}[/bold]")
    console.print(f"   Private key (encrypted): [bold]{get_store_host_key_path(store, host_id)}[/bold]")

    return Success(None)


def export_host_key_unencrypted_wrapper(
    ctx: Context,
    host_id: str, 
    store: "models.Store", 
    out_path: str | None = None
) -> Result[None, str]:
    """Export an unencrypted private key for a host.

    Args:
    ----
        ctx: Click context
        host_id: Host ID for the key
        store: Store object (already unlocked with password)
        out_path: Path to save the unencrypted key (if None, print to console)

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Check if host key exists
    if not host_exists(store, host_id):
        return Failure(f"Host {host_id} not found in store")

    # Load the encrypted key
    key_result = read_host_key(store, host_id)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load host key: {key_result.error}")
    
    private_key = key_result.unwrap()
    
    # Export the unencrypted key
    if out_path:
        # Export to file
        out_file_path = Path(out_path)
        export_result = export_unencrypted_key(private_key, out_file_path)
        if isinstance(export_result, Failure):
            return Failure(f"Failed to export unencrypted key: {export_result.error}")
            
        console.print(f"✅ Unencrypted key exported to [bold]{out_file_path}[/bold]")
    else:
        # Print to console
        key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        console.print(key_bytes.decode("utf-8"))
        
    return Success(None)


def deploy_host(
    ctx: Context,
    host_id: str, 
    config: "models.Config", 
    store: "models.Store"
) -> Result[None, str]:
    """Run the deployment script for a host.

    Args:
    ----
        ctx: Click context
        host_id: Host ID to deploy
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")
        
    # Get configurations from the Config object
    hosts_config = config.hosts_config
    
    # Find host config in the dictionary
    if host_id not in hosts_config:
        return Failure(f"Host {host_id} not found in hosts configuration")
    
    host_config = hosts_config[host_id]
    
    # Check if deployment command is configured
    if host_config.deploy is None or not host_config.deploy.command:
        return Failure(f"No deployment command configured for host {host_id}")
    
    deploy_command = host_config.deploy.command
    
    # Load host certificate and key
    cert_result = read_host_cert(store, host_id)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load host certificate: {cert_result.error}")
    cert = cert_result.unwrap()
    
    key_result = read_host_key(store, host_id)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load host key: {key_result.error}")
    private_key = key_result.unwrap()
    
    # Run deployment command
    console.print(f"Running deployment command for [bold]{host_id}[/bold]...")
    deploy_result = deploy(deploy_command, cert, private_key)
    if isinstance(deploy_result, Failure):
        return Failure(f"Deployment failed: {deploy_result.error}")
    
    console.print(f"✅ Deployment completed successfully for [bold]{host_id}[/bold]")
    console.print(f"   Command: {deploy_command}")
    
    return Success(None)


def deploy_all_hosts(
    ctx: Context,
    config: "models.Config", 
    store: "models.Store"
) -> Result[None, str]:
    """Deploy all host certificates.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get configurations from Config object
    hosts_config = config.hosts_config
    host_ids = list(hosts_config.keys())
    
    if not host_ids:
        return Failure("No hosts found in configuration")
    
    console.print(f"Deploying {len(host_ids)} hosts...")
    
    success_count = 0
    error_count = 0
    
    for host_id in host_ids:
        console.print(f"\nProcessing host: [bold]{host_id}[/bold]")
        
        # Skip hosts without deployment configuration
        host_config = hosts_config[host_id]
        if host_config.deploy is None or not host_config.deploy.command:
            console.print(f"[yellow]Skipping {host_id} - no deployment command configured[/yellow]")
            continue
            
        deploy_result = deploy_host(ctx, host_id, config, store)
        
        if isinstance(deploy_result, Success):
            success_count += 1
        else:
            error_count += 1
            console.print(f"[bold red]Error:[/bold red] {deploy_result.error if isinstance(deploy_result, Failure) else 'Unknown error'}")
    
    # Print summary
    console.print(f"\n✅ Successfully deployed {success_count} certificates")
    if error_count > 0:
        console.print(f"❌ Failed to deploy {error_count} certificates")
    
    return Success(None)


def get_certificates_list_dict(
    store: "models.Store", expired: bool = False, expiring_days: int | None = None
) -> Result[dict[str, Any], str]:
    """Get a dictionary with certificate list information.

    Args:
    ----
        store: Store object containing certificate information
        expired: Only include expired certificates if True
        expiring_days: Only include certificates expiring within this many days

    Returns:
    -------
        Result with certificate info dictionary or error message

    """
    # Make sure store is unlocked
    if not store.unlocked:
        return Failure("Store must be unlocked")
    
    # Load CA certificate
    ca_cert_result = read_ca_cert(store)
    if isinstance(ca_cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {ca_cert_result.error}")
    ca_cert = ca_cert_result.unwrap()

    # Get CA information
    ca_not_before = ca_cert.not_valid_before
    ca_not_after = ca_cert.not_valid_after
    ca_serial = format(ca_cert.serial_number, "x")
    
    # Calculate days until CA expiration
    now = datetime.datetime.now(datetime.UTC)
    ca_days_remaining = (ca_not_after.replace(tzinfo=datetime.UTC) - now).days
    
    # Prepare CA info for result
    ca_info = {
        "serial": ca_serial,
        "not_before": ca_not_before.isoformat(),
        "not_after": ca_not_after.isoformat(),
        "days_remaining": ca_days_remaining,
    }
    
    # List host directories
    hosts_list_result = store_list_hosts(store)
    if isinstance(hosts_list_result, Failure):
        return Failure(f"Failed to list hosts: {hosts_list_result.error}")
    host_ids = hosts_list_result.unwrap()
    
    # Build filtered host list
    filtered_hosts = []
    
    for host_id in host_ids:
        # Get host certificate
        cert_result = read_host_cert(store, host_id)
        if isinstance(cert_result, Failure):
            # Skip hosts with certificate read errors
            continue
            
        cert = cert_result.unwrap()
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        serial = format(cert.serial_number, "x")
        
        # Calculate days until expiration
        days_remaining = (not_after.replace(tzinfo=datetime.UTC) - now).days
        
        # Apply filters
        if expired and days_remaining >= 0:
            continue
            
        if expiring_days is not None and days_remaining > expiring_days:
            continue
            
        # Create fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint = f"SHA256:{fingerprint}"
            
        host_info = {
            "host_id": host_id,
            "serial": serial,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "fingerprint": fingerprint
        }
        
        filtered_hosts.append(host_info)
    
    # Return full data structure
    return Success({
        "ca": ca_info,
        "hosts": filtered_hosts,
        "total": len(filtered_hosts),
        "filters": {"expired": expired, "expiring_days": expiring_days},
    })


def list_certificates(
    ctx: Context,
    store: "models.Store", 
    expired: bool = False, 
    expiring_days: int | None = None
) -> Result[None, str]:
    """List certificates with their expiration dates.

    Args:
    ----
        ctx: Click context
        store: Store object containing certificate information
        expired: Only include expired certificates if True
        expiring_days: Only include certificates expiring within this many days

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Get certificates list as dictionary 
    result = get_certificates_list_dict(store, expired, expiring_days)
    if isinstance(result, Failure):
        return result
    
    data = result.unwrap()
    ca_info = data["ca"]
    hosts = data["hosts"]
    
    # Display CA information
    ca_table = Table(title="CA Certificate")
    ca_table.add_column("Serial")
    ca_table.add_column("Expiration Date")
    ca_table.add_column("Days Remaining")
    
    # Format CA days remaining with color
    ca_days_remaining = ca_info["days_remaining"]
    days_formatted = ""
    if ca_days_remaining < 0:
        days_formatted = f"[bold red]{ca_days_remaining} (expired)[/bold red]"
    elif ca_days_remaining < EXPIRY_CRITICAL_DAYS:
        days_formatted = f"[bold red]{ca_days_remaining}[/bold red]"
    elif ca_days_remaining < EXPIRY_WARNING_DAYS:
        days_formatted = f"[bold yellow]{ca_days_remaining}[/bold yellow]"
    else:
        days_formatted = str(ca_days_remaining)
        
    ca_table.add_row(
        ca_info["serial"],
        ca_info["not_after"],
        days_formatted
    )
    
    console.print(ca_table)
    
    # Check if we have any hosts
    if not hosts:
        console.print("\nNo host certificates match the criteria")
        return Success(None)
        
    # Host table
    host_table = Table(title="Host Certificates")
    host_table.add_column("Host ID")
    host_table.add_column("Serial")
    host_table.add_column("Expiration Date")
    host_table.add_column("Days Remaining")
    host_table.add_column("Fingerprint")
    
    # Sort hosts by name
    sorted_hosts = sorted(hosts, key=lambda x: x["host_id"])
    
    for host in sorted_hosts:
        # Format days remaining with color
        days = host["days_remaining"]
        days_str = ""
        if days < 0:
            days_str = f"[bold red]{days} (expired)[/bold red]"
        elif days < EXPIRY_CRITICAL_DAYS:
            days_str = f"[bold red]{days}[/bold red]"
        elif days < EXPIRY_WARNING_DAYS:
            days_str = f"[bold yellow]{days}[/bold yellow]"
        else:
            days_str = str(days)
            
        host_table.add_row(
            host["host_id"],
            host["serial"],
            host["not_after"],
            days_str,
            host["fingerprint"]
        )
        
    console.print("\n")
    console.print(host_table)
    
    return Success(None)


def clean_certificates(
    ctx: Context,
    config: "models.Config",
    store: "models.Store"
) -> Result[None, str]:
    """Remove host folders that are no longer in the configuration.

    Args:
    ----
        ctx: Click context
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked:
        return Failure("Store must be unlocked")
    
    # Get configured hosts from config
    hosts_config = config.hosts_config
    configured_hosts = list(hosts_config.keys()) if hosts_config else []
    
    # Get existing host directories 
    existing_hosts_result = store_list_hosts(store)
    if isinstance(existing_hosts_result, Failure):
        return Failure(f"Failed to list hosts: {existing_hosts_result.error}")

    existing_hosts = existing_hosts_result.unwrap()

    # Find hosts to remove
    hosts_to_remove = [host for host in existing_hosts if host not in configured_hosts]

    if not hosts_to_remove:
        console.print("✅ No unconfigured host folders found.")
        return Success(None)

    # Remove each host
    removed_hosts = []
    for host_id in hosts_to_remove:
        console.print(f"Removing host folder: [bold]{host_id}[/bold]")
        delete_result = delete_host(store, host_id)
        if isinstance(delete_result, Success):
            removed_hosts.append(host_id)
            console.print(f"✅ Removed host folder for [bold]{host_id}[/bold]")
        else:
            console.print(f"[bold red]Error:[/bold red] Failed to remove {host_id}: {delete_result.error}")

    # Print summary
    if removed_hosts:
        console.print(f"\n✅ Removed {len(removed_hosts)} host folders:")
        for host_id in removed_hosts:
            console.print(f"   - [bold]{host_id}[/bold]")

    return Success(None)


def get_host_info(hostname: str, store_path: str) -> Result[dict[str, Any], str]:
    """Get detailed information about a host certificate.

    Args:
    ----
        hostname: Hostname to get info for
        store_path: Path to the certificate store

    Returns:
    -------
        Result with host info dict or error message

    """
    # Check if host exists
    if not host_exists(store_path, hostname):
        return Failure(f"Host {hostname} not found in store")

    # Get host certificate
    cert_result = read_host_cert(store_path, hostname)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load host certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if isinstance(cert_deserialize_result, Failure):
        return Failure(f"Failed to deserialize certificate: {cert_deserialize_result.error}")

    cert = cert_deserialize_result.unwrap()

    # Get host info from inventory
    host_info_result = inventory_get_host_info(Path(store_path), hostname, cert)
    if isinstance(host_info_result, Failure):
        return Failure(f"Failed to get host info from inventory: {host_info_result.error}")

    host_info = host_info_result.unwrap()

    return Success(host_info)


def process_csr(
    ctx: Context,
    csr_path: str,
    config: "models.Config",
    store: "models.Store",
    validity_days: int = 365,
    out_path: str | None = None,
) -> Result[None, str]:
    """Process a Certificate Signing Request.

    Args:
    ----
        ctx: Click context
        csr_path: Path to the CSR file
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        validity_days: Number of days the certificate should be valid
        out_path: Optional path to save the signed certificate to

    Returns:
    -------
        Result with None for success or error message

    """
    console = ctx.obj["console"]
    
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Load CSR
    try:
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data)
    except Exception as e:
        return Failure(f"Failed to load CSR: {str(e)}")

    # Verify CSR signature
    if not csr.is_signature_valid:
        return Failure("CSR has an invalid signature")

    # Extract hostname from common name
    hostname = None
    for attr in csr.subject:
        if attr.oid == NameOID.COMMON_NAME:
            # Handle both string and bytes value types
            hostname = attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
            break

    if not hostname:
        return Failure("Could not extract hostname from CSR")

    # Load the CA certificate
    cert_result = read_ca_cert(store)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load CA certificate: {cert_result.error}")
    ca_cert = cert_result.unwrap()
    
    # Load the CA key
    key_result = read_ca_key(store)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to load CA key: {key_result.error}")
    ca_key = key_result.unwrap()

    # Get hash algorithm from config
    hash_algorithm = config.ca_config.hash_algorithm

    # Extract SANs from CSR
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
                    # Format directory name
                    dn_parts = []
                    for attr in san.value:
                        oid = attr.oid
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

                    alt_names.directory_name.append(",".join(dn_parts) if dn_parts else "")

    # Extract subject identity from CSR subject
    subject_identity = SubjectIdentity(
        common_name=hostname,
        organization="",
        organization_unit="",
        country="",
        state="",
        locality="",
        email="",
    )

    # Extract subject components from the CSR
    for attr in csr.subject:
        attr_value = str(attr.value)
        if attr.oid == NameOID.ORGANIZATION_NAME:
            subject_identity.organization = attr_value
        elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            subject_identity.organization_unit = attr_value
        elif attr.oid == NameOID.COUNTRY_NAME:
            subject_identity.country = attr_value
        elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
            subject_identity.state = attr_value
        elif attr.oid == NameOID.LOCALITY_NAME:
            subject_identity.locality = attr_value
        elif attr.oid == NameOID.EMAIL_ADDRESS:
            subject_identity.email = attr_value

    # Create CA object
    ca_obj = CA(
        ca_config=config.ca_config,
        cert=ca_cert,
        key=ca_key,
    )

    # Create certificate parameters
    cert_params = CertificateParams(
        subject_identity=subject_identity,
        ca=ca_obj,
        private_key=None,  # We'll use the public key from the CSR
        validity_days=validity_days,
        alt_names=alt_names if not alt_names.is_empty() else None,
        hash_algorithm=hash_algorithm,
    )

    # Create certificate
    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate from CSR: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save to file if out_path provided
    if out_path:
        out_file_path = Path(out_path)
        try:
            # Ensure parent directory exists
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save the certificate
            with open(out_file_path, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))
        except Exception as e:
            return Failure(f"Failed to save certificate to {out_path}: {str(e)}")

    # Print success message
    console.print(f"✅ Successfully signed CSR for [bold]{hostname}[/bold]")

    if out_path:
        console.print(f"   Certificate saved to: [bold]{out_path}[/bold]")

    # Print subject information
    console.print("   Subject:")
    for attr in csr.subject:
        attr_name = attr.oid._name
        # Ensure we have a string value
        if isinstance(attr.value, bytes):
            attr_value = attr.value.decode("utf-8")
        else:
            attr_value = str(attr.value)
        console.print(f"     {attr_name}: {attr_value}")

    # Print SANs if present
    if not alt_names.is_empty():
        console.print("   Subject Alternative Names:")
        for name_type in ["dns", "ip", "email", "uri", "directory_name"]:
            values = getattr(alt_names, name_type, [])
            if values:
                console.print(f"     {name_type}: {', '.join(values)}")

    return Success(None)
