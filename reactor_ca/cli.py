#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool.

This module provides a Click CLI interface for the ReactorCA tool.
It connects user commands to the ca and host modules which implement
the actual functionality.
"""

import json
import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from reactor_ca import __version__
from reactor_ca.ca import (
    get_ca_info,
    issue_ca,
    rekey_ca,
)
from reactor_ca.ca import (
    import_ca as import_ca_func,
)
from reactor_ca.config import (
    init_config_files,
    load_config,
    validate_config_files,
)
from reactor_ca.host import (
    clean_certificates,
    deploy_all_hosts,
    deploy_host,
    issue_all_certificates,
    issue_certificate,
    list_certificates,
    process_csr,
    rekey_all_hosts,
    rekey_host,
)
from reactor_ca.host import (
    export_host_key_unencrypted_wrapper as export_host_key_unencrypted,
)
from reactor_ca.host import (
    import_host_key as import_host_key_func,
)
from reactor_ca.models import Store, ValidityConfig
from reactor_ca.password import get_password as get_password_func
from reactor_ca.paths import (
    get_ca_config_path,
    get_hosts_config_path,
)
from reactor_ca.result import Failure, Success
from reactor_ca.store import (
    ca_exists,
    initialize_store,
    unlock,
)
from reactor_ca.store import change_password as change_password_func

# Constants for certificate expiration warnings
WARNING_DAYS = 90
CRITICAL_DAYS = 30

# Create console instance for rich output
console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option("root_path", "--root", type=click.Path(exists=False), help="Root directory (with config and store subdirectories)")
@click.option("config_path", "--config", type=click.Path(exists=False), help="Path to configuration directory")
@click.option("store_path", "--store", type=click.Path(exists=False), help="Path to certificate store directory")
@click.pass_context
def cli(
    ctx: click.Context,
    root_path: str | None = None,
    config_path: str | None = None,
    store_path: str | None = None,
) -> None:
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    ctx.ensure_object(dict)

    app_config = load_config(root_path, config_path, store_path)

    if isinstance(app_config, Failure):
        console.print(f"[bold red]Error:[/bold red] {app_config.error}")
        ctx.exit(1)

    store_obj = Store(path=app_config.value.store_path, password=None, unlocked=False)

    # If password was provided, try to unlock the store
    if password:
        unlock(store_obj, password)
        # We don't need to handle errors here - if unlock fails, the store
        # will remain locked and commands will prompt for password as needed

    # Store the objects for subcommands
    ctx.obj = {"config": config_result.value, "store": store_obj}


# Configuration commands
@cli.group()
def config() -> None:
    """Manage configuration files."""
    pass


@config.command(name="init")
@click.option("--force", is_flag=True, help="Force overwrite of existing config files")
@click.pass_context
def config_init(ctx: click.Context, force: bool) -> None:
    """Initialize configuration files."""
    config = ctx.obj["config"]
    ctx.obj["store"]

    # Make sure the directories exist
    os.makedirs(config.config_path, exist_ok=True)
    os.makedirs(config.store_path, exist_ok=True)

    # Initialize store
    initialize_result = initialize_store(config.store_path)
    if isinstance(initialize_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {initialize_result.error}")
        ctx.exit(1)

    # Convert paths to Path objects
    config_path = Path(config.config_path)
    store_path = Path(config.store_path)

    # Initialize config files
    try:
        init_result = init_config_files(config_path, store_path, force)
        if isinstance(init_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {init_result.error}")
            ctx.exit(1)
        console.print("✅ Configuration files initialized successfully")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        ctx.exit(1)


@config.command(name="validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate configuration files against schemas."""
    config = ctx.obj["config"]

    # The configs were already validated during load_config
    # Just display that they are valid
    console.print("✅ All configuration files are valid")

    # For a more explicit validation:
    # Get paths to config files
    ca_config_path = get_ca_config_path(config)
    hosts_config_path = get_hosts_config_path(config)

    # Validate both config files
    result = validate_config_files(ca_config_path, hosts_config_path)

    if isinstance(result, Failure):
        # The error messages are already printed by validate_config_files
        ctx.exit(1)


# CA management commands
@cli.group()
def ca() -> None:
    """Certificate Authority management commands."""
    pass


@ca.command(name="issue")
@click.pass_context
def ca_issue(ctx: click.Context) -> None:
    """Create or renew a CA certificate."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=not ca_exists(store.path),  # Only confirm if creating new CA
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Issue CA certificate
    # Use the store.password that's already set
    result = issue_ca(config, store)

    if isinstance(result, Success):
        info = result.unwrap()
        action = info["action"]

        if action == "created":
            console.print("✅ CA created successfully")
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
            console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")
        else:
            console.print("✅ CA certificate renewed successfully")
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")

        console.print("📋 Inventory updated")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@ca.command(name="import")
@click.option("--cert", required=True, type=click.Path(exists=True), help="Path to CA certificate file")
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to CA private key file")
@click.option("--key-password", help="Password for the source key file")
@click.pass_context
def ca_import(ctx: click.Context, cert: str, key: str, key_password: str | None = None) -> None:
    """Import an existing CA."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password for saving imported CA: ",
            confirm=True,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Import CA
    result = import_ca_func(Path(cert), Path(key), config, store, key_password)

    if isinstance(result, Success):
        info = result.unwrap()
        console.print("✅ CA imported successfully")
        console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
        console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")
        console.print("📋 Inventory updated")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@ca.command(name="rekey")
@click.pass_context
def ca_rekey(ctx: click.Context) -> None:
    """Generate a new key and renew the CA certificate."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Rekey CA
    result = rekey_ca(config, store)

    if isinstance(result, Success):
        info = result.unwrap()
        console.print("✅ CA rekeyed successfully")
        console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
        console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")
        console.print("📋 Inventory updated")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@ca.command(name="info")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.pass_context
def ca_info(ctx: click.Context, json_output: bool) -> None:
    """Show information about the Certificate Authority."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Get CA info
    result = get_ca_info(store)

    if isinstance(result, Success):
        info = result.unwrap()

        if json_output:
            console.print(json.dumps(info, indent=2))
        else:
            # Display in rich table format
            console.print("[bold]CA Certificate Information[/bold]")

            # Subject information
            subject_info = info["subject"]
            console.print(f"Subject: {subject_info.get('commonName', '')}")
            console.print(f"Organization: {subject_info.get('organizationName', '')}")
            console.print(f"Organizational Unit: {subject_info.get('organizationalUnitName', '')}")
            console.print(f"Country: {subject_info.get('countryName', '')}")
            console.print(f"State/Province: {subject_info.get('stateOrProvinceName', '')}")
            console.print(f"Locality: {subject_info.get('localityName', '')}")
            console.print(f"Email: {subject_info.get('emailAddress', '')}")

            # Certificate details
            console.print(f"Serial: {info['serial']}")
            console.print(f"Valid From: {info['not_before']}")
            console.print(f"Valid Until: {info['not_after']}")

            # Format days remaining with color based on how soon it expires
            days_remaining = info["days_remaining"]
            if days_remaining < 0:
                console.print(f"Days Remaining: [bold red]{days_remaining} (expired)[/bold red]")
            elif days_remaining < CRITICAL_DAYS:
                console.print(f"Days Remaining: [bold red]{days_remaining}[/bold red]")
            elif days_remaining < WARNING_DAYS:
                console.print(f"Days Remaining: [bold yellow]{days_remaining}[/bold yellow]")
            else:
                console.print(f"Days Remaining: {days_remaining}")

            console.print(f"Fingerprint: {info['fingerprint']}")
            console.print(f"Public Key Type: {info['public_key']['type']}")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


# Host certificate operations
@cli.group()
def host() -> None:
    """Host certificate operations."""
    pass


@host.command(name="issue")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Issue certificates for all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
@click.pass_context
def host_issue(ctx: click.Context, hostname: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Create or renew certificates for hosts."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        ctx.exit(1)

    if all_hosts:
        # Issue certificates for all hosts
        result = issue_all_certificates(config, store, no_export=no_export, do_deploy=deploy)

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(f"\n✅ Successfully processed {info['success']} certificates")
            if info["error"] > 0:
                console.print(f"❌ Failed to process {info['error']} certificates")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)
    else:
        # Issue certificate for a single host
        assert hostname is not None  # for type checking
        result = issue_certificate(hostname, config, store, no_export=no_export, do_deploy=deploy)

        if isinstance(result, Success):
            info = result.unwrap()
            action = "created" if info["is_new"] else "renewed"

            console.print(f"✅ Certificate {action} successfully for [bold]{hostname}[/bold]")
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
            if info["is_new"]:
                console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")

            if "export" in info:
                export_info = info["export"]
                if "cert" in export_info:
                    console.print(f"✅ Certificate exported to [bold]{export_info['cert']}[/bold]")
                if "chain" in export_info:
                    console.print(f"✅ Certificate chain exported to [bold]{export_info['chain']}[/bold]")

            if "deploy" in info:
                console.print("✅ Deployment command executed successfully")

            console.print("📋 Inventory updated")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)


@host.command(name="import-key")
@click.argument("hostname", required=True)
@click.option("--key", required=True, type=click.Path(exists=True), help="Path to private key file")
@click.pass_context
def host_import_key(ctx: click.Context, hostname: str, key: str) -> None:
    """Import an existing key for a host."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Import host key
    result = import_host_key_func(hostname, key, config, store)

    if isinstance(result, Success):
        info = result.unwrap()
        console.print(f"✅ Key imported successfully for [bold]{hostname}[/bold]")
        console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@host.command(name="export-key")
@click.argument("hostname", required=True)
@click.option("--out", help="Path to output file (stdout if not provided)")
@click.pass_context
def host_export_key(ctx: click.Context, hostname: str, out: str | None) -> None:
    """Export unencrypted private key for a host."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Export host key
    result = export_host_key_unencrypted(hostname, store, out)

    if isinstance(result, Success):
        info = result.unwrap()
        if "export_path" in info:
            console.print(f"✅ Unencrypted key exported to [bold]{info['export_path']}[/bold]")
        elif "key_data" in info:
            # Just print the key data to stdout
            console.print(info["key_data"])
    else:
        if isinstance(result, Failure):
            console.print(f"[bold red]Error:[/bold red] {result.error}")
        else:
            console.print("[bold red]Error:[/bold red] Unknown error")
        ctx.exit(1)


@host.command(name="rekey")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Rekey all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
@click.pass_context
def host_rekey(ctx: click.Context, hostname: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Generate new keys and certificates for hosts."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        ctx.exit(1)

    if all_hosts:
        # Rekey all hosts
        result = rekey_all_hosts(config, store, no_export=no_export, do_deploy=deploy)

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(f"\n✅ Successfully rekeyed {info['success']} certificates")
            if info["error"] > 0:
                console.print(f"❌ Failed to rekey {info['error']} certificates")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)
    else:
        # Rekey a single host
        assert hostname is not None  # for type checking
        result = rekey_host(hostname, config, store, no_export=no_export, do_deploy=deploy)

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(f"✅ Certificate and key rekeyed successfully for [bold]{hostname}[/bold]")
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
            console.print(f"   Private key (encrypted): [bold]{info['key_path']}[/bold]")

            if "export" in info:
                export_info = info["export"]
                if "cert" in export_info:
                    console.print(f"✅ Certificate exported to [bold]{export_info['cert']}[/bold]")
                if "chain" in export_info:
                    console.print(f"✅ Certificate chain exported to [bold]{export_info['chain']}[/bold]")

            if "deploy" in info:
                console.print("✅ Deployment command executed successfully")

            console.print("📋 Inventory updated")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)


@host.command(name="list")
@click.option("--expired", is_flag=True, help="Only show expired certificates")
@click.option("--expiring", type=int, help="Show certificates expiring within days")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.pass_context
def host_list(ctx: click.Context, expired: bool, expiring: int | None, json_output: bool) -> None:
    """List certificates with their expiration dates."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # List certificates
    result = list_certificates(store, expired=expired, expiring_days=expiring)

    if isinstance(result, Success):
        info = result.unwrap()

        if json_output:
            console.print(json.dumps(info, indent=2))
        else:
            # Display in rich table format
            ca_info = info["ca"]
            hosts = info["hosts"]

            # CA table
            ca_table = Table(title="CA Certificate")
            ca_table.add_column("Serial")
            ca_table.add_column("Expiration Date")
            ca_table.add_column("Days Remaining")
            ca_table.add_column("Fingerprint")

            # Format CA days remaining with color
            days_remaining = ca_info["days_remaining"]
            days_formatted = ""
            if days_remaining < 0:
                days_formatted = f"[bold red]{days_remaining} (expired)[/bold red]"
            elif days_remaining < CRITICAL_DAYS:
                days_formatted = f"[bold red]{days_remaining}[/bold red]"
            elif days_remaining < WARNING_DAYS:
                days_formatted = f"[bold yellow]{days_remaining}[/bold yellow]"
            else:
                days_formatted = str(days_remaining)

            ca_table.add_row(ca_info["serial"], ca_info["not_after"], days_formatted, ca_info["fingerprint"])

            console.print(ca_table)

            # Check if we have any hosts
            if not hosts:
                console.print("\nNo host certificates match the criteria")
                return

            # Host table
            host_table = Table(title="Host Certificates")
            host_table.add_column("Hostname")
            host_table.add_column("Serial")
            host_table.add_column("Expiration Date")
            host_table.add_column("Days Remaining")
            host_table.add_column("Fingerprint")
            host_table.add_column("Renewals")

            # Sort hosts by name
            sorted_hosts = sorted(hosts, key=lambda x: x.get("name", ""))

            for host in sorted_hosts:
                # Format days remaining with color
                days = host["days_remaining"]
                days_str = ""
                if days < 0:
                    days_str = f"[bold red]{days} (expired)[/bold red]"
                elif days < CRITICAL_DAYS:
                    days_str = f"[bold red]{days}[/bold red]"
                elif days < WARNING_DAYS:
                    days_str = f"[bold yellow]{days}[/bold yellow]"
                else:
                    days_str = str(days)

                host_table.add_row(
                    host["name"],
                    host["serial"],
                    host["not_after"],
                    days_str,
                    host["fingerprint"],
                    str(host["renewal_count"]),
                )

            console.print("\n")
            console.print(host_table)
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@host.command(name="deploy")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Deploy all hosts")
@click.pass_context
def host_deploy(ctx: click.Context, hostname: str | None, all_hosts: bool) -> None:
    """Deploy certificates to configured destinations."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        ctx.exit(1)

    if all_hosts:
        # Deploy all hosts
        result = deploy_all_hosts(config, store)

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(f"\n✅ Successfully deployed {info['success']} certificates")
            if info["error"] > 0:
                console.print(f"❌ Failed to deploy {info['error']} certificates")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)
    else:
        # Deploy a single host
        assert hostname is not None  # for type checking
        result = deploy_host(hostname, config, store)

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(f"✅ Deployment completed successfully for [bold]{hostname}[/bold]")
            console.print(f"   Command: {info['command']}")
        else:
            console.print(
                f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
            )
            ctx.exit(1)


@host.command(name="clean")
@click.pass_context
def host_clean(ctx: click.Context) -> None:
    """Remove host folders that are no longer in the configuration."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Clean certificates
    result = clean_certificates(store.path)

    if isinstance(result, Success):
        info = result.unwrap()
        removed_hosts = info["removed"]

        if not removed_hosts:
            console.print("✅ No unconfigured host folders found.")
        else:
            console.print(f"✅ Removed {len(removed_hosts)} host folders:")
            for hostname in removed_hosts:
                console.print(f"   - [bold]{hostname}[/bold]")
            console.print("📋 Inventory updated")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


@host.command(name="sign-csr")
@click.option("--csr", required=True, type=click.Path(exists=True), help="Path to the CSR file")
@click.option("--out", required=True, help="Output path for the signed certificate")
@click.option("--validity-days", type=int, default=None, help="Validity period in days")
@click.option("--validity-years", type=int, default=None, help="Validity period in years")
@click.pass_context
def host_sign_csr(
    ctx: click.Context, csr: str, out: str, validity_days: int | None, validity_years: int | None
) -> None:
    """Sign a CSR and output the certificate."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Calculate validity period
    if validity_days is not None and validity_years is not None:
        console.print("[bold red]Error:[/bold red] Cannot specify both --validity-days and --validity-years")
        ctx.exit(1)

    validity_config = ValidityConfig(days=validity_days, years=validity_years)
    validity = validity_config.to_days()

    # Process CSR
    result = process_csr(csr, config, store, validity_days=validity, out_path=out)

    if isinstance(result, Success):
        info = result.unwrap()
        hostname = info["hostname"]
        console.print(f"✅ Successfully signed CSR for [bold]{hostname}[/bold]")
        console.print(f"   Certificate saved to: [bold]{info['cert_path']}[/bold]")

        # If we have subject info, display it
        if "subject" in info and info["subject"]:
            console.print("   Subject:")
            for key, value in info["subject"].items():
                console.print(f"     {key}: {value}")

        # If we have SANs, display them
        if "sans" in info and info["sans"]:
            console.print("   Subject Alternative Names:")
            for san_type, values in info["sans"].items():
                console.print(f"     {san_type}: {', '.join(values)}")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


# Utility operations
@cli.group()
def util() -> None:
    """Perform utility operations."""
    pass


@util.command(name="passwd")
@click.pass_context
def util_passwd(ctx: click.Context) -> None:
    """Change password for all encrypted keys."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]

    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password_func(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter current CA master password: ",
            confirm=False,
        )
        if isinstance(password_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)

        # Unlock the store
        unlock_result = unlock(store, password_result.unwrap())
        if isinstance(unlock_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)

    # Get current password
    console.print("You will need to provide the current password and then the new password.")

    # Get new password
    new_password_result = get_password_func(
        min_length=config.ca_config.password.min_length,
        password_file=config.ca_config.password.file,
        env_var=config.ca_config.password.env_var,
        prompt_message="Enter new CA master password: ",
        confirm=True,
    )
    if isinstance(new_password_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {new_password_result.error}")
        ctx.exit(1)

    new_password = new_password_result.unwrap()

    # Change passwords (helper function will handle all UI)
    result = change_password_func(store, store.password or "", new_password)

    if result:
        console.print("✅ Password changed successfully for all keys")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


if __name__ == "__main__":
    cli()
