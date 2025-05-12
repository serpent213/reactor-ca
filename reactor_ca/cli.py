#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool.

This module provides a Click CLI interface for the ReactorCA tool.
It connects user commands to the ca and host modules which implement
the actual functionality.
"""

import json
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from reactor_ca import __version__
from reactor_ca.cli_ca import get_ca_info, import_ca, issue_ca, rekey_ca
from reactor_ca.config import create as create_config
from reactor_ca.config import init as init_config
from reactor_ca.config import validate as validate_config
from reactor_ca.defaults import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS
from reactor_ca.cli_host import clean_certificates, deploy_all_hosts, deploy_host
from reactor_ca.cli_host import \
    export_host_key_unencrypted_wrapper as export_host_key_unencrypted
from reactor_ca.cli_host import import_host_key as import_host_key_func
from reactor_ca.cli_host import (issue_all_certificates, issue_certificate,
                             list_certificates, process_csr, rekey_all_hosts,
                             rekey_host)
from reactor_ca.models import Config, Store, ValidityConfig
from reactor_ca.password import get_password
from reactor_ca.paths import get_log_path, resolve_paths
from reactor_ca.result import Failure, Success
from reactor_ca.store import change_password
from reactor_ca.store import create as create_store
from reactor_ca.store import init as init_store
from reactor_ca.store import unlock


def init_config_and_store(ctx: click.Context, mode: str) -> tuple[Config, Store | None]:
    """Initialize config and store based on the requested mode, initialize logger.

    Args:
    ----
        ctx: Click context containing path information
        mode: One of 'config', 'store', or 'unlock'

    Returns:
    -------
        Tuple of (config, store) objects. If mode='config', store will be None.
        If initialization fails, the function will exit the program.

    """
    console = ctx.obj["console"]
    config_path = ctx.obj["config_dir"]
    store_path = ctx.obj["store_dir"]

    # Initialize config (required for all modes)
    config_result = init_config(config_path)
    if isinstance(config_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {config_result.error}")
        console.print('Run "ca config init" to initialise the CA.')
        ctx.exit(1)
    config = config_result.value

    logging.basicConfig(
        filename=get_log_path(store_path),
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    store = None
    if mode in {"store", "unlock"}:
        # Store and unlock modes need store initialized
        store_result = init_store(store_path)
        if isinstance(store_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {store_result.error}")
            ctx.exit(1)
        store = store_result.value

        if mode == "unlock":
            # Unlock mode needs to unlock the store
            # Get password
            if config.ca_config is None:
                console.print("[bold red]Error:[/bold red] No CA configuration found")
                ctx.exit(1)

            password_result = get_password(
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
            store = unlock_result.value

    return config, store


# Removing this function as it's no longer needed with the new store.py interface


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--root",
    "root_path",
    type=click.Path(exists=False, path_type=Path),
    help="Root directory (with config and store subdirectories)",
    envvar="REACTOR_CA_ROOT",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False, path_type=Path),
    help="Path to configuration directory",
    envvar="REACTOR_CA_CONFIG_DIR",
)
@click.option(
    "--store",
    "store_path",
    type=click.Path(exists=False, path_type=Path),
    help="Path to certificate store directory",
    envvar="REACTOR_CA_STORE_DIR",
)
@click.pass_context
def cli(
    ctx: click.Context,
    root_path: Path | None = None,
    config_path: Path | None = None,
    store_path: Path | None = None,
) -> None:
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    ctx.ensure_object(dict)
    ctx.obj["console"] = Console()

    config_path, store_path = resolve_paths(root_path, config_path, store_path)
    ctx.obj["config_dir"] = config_path
    ctx.obj["store_dir"] = store_path


# Configuration commands
@cli.group()
@click.pass_context
def config(_ctx: click.Context) -> None:
    """Manage configuration files."""
    pass


@config.command(name="init")
@click.option("--force", is_flag=True, help="Force overwrite of existing config files")
@click.pass_context
def config_init(ctx: click.Context, force: bool) -> None:
    """Initialize configuration files."""
    console = ctx.obj["console"]
    config_path = Path(ctx.obj["config_dir"])
    store_path = Path(ctx.obj["store_dir"])

    config_result = create_config(config_path)
    if isinstance(config_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {config_result.error}")
        ctx.exit(1)

    store_result = create_store(store_path)
    if isinstance(store_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {store_result.error}")
        ctx.exit(1)

    console.print("✅ Configuration files initialized successfully")
    console.print(f"   Config directory: [bold]{config_path}[/bold]")
    console.print(f"   Store directory: [bold]{store_path}[/bold]")


@config.command(name="validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate configuration files against schemas."""
    config_path = Path(ctx.obj["config_dir"])
    console = ctx.obj["console"]

    # Use the new validate_config function
    result = validate_config(config_path)

    if isinstance(result, Success):
        console.print("✅ All configuration files are valid")
    else:
        # The error messages should already be printed by validate_config
        ctx.exit(1)


# CA management commands
@cli.group()
@click.pass_context
def ca(ctx: click.Context) -> None:
    """Certificate Authority management commands."""
    pass


@ca.command(name="issue")
@click.pass_context
def ca_issue(ctx: click.Context) -> None:
    """Create or renew a CA certificate."""
    console = ctx.obj["console"]
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None

    # Issue CA certificate
    result = issue_ca(ctx, config, store)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@ca.command(name="import")
@click.option(
    "--cert",
    required=True,
    type=click.Path(exists=True),
    help="Path to CA certificate file",
)
@click.option(
    "--key",
    required=True,
    type=click.Path(exists=True),
    help="Path to CA private key file",
)
@click.option("--key-password", help="Password for the source key file")
@click.pass_context
def ca_import(
    ctx: click.Context, cert: str, key: str, key_password: str | None = None
) -> None:
    """Import an existing CA."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    # Import CA
    result = import_ca(Path(cert), Path(key), config, store, key_password)

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
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

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
    # Initialize config and store
    _, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

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
            console.print(
                f"Organizational Unit: {subject_info.get('organizationalUnitName', '')}"
            )
            console.print(f"Country: {subject_info.get('countryName', '')}")
            console.print(
                f"State/Province: {subject_info.get('stateOrProvinceName', '')}"
            )
            console.print(f"Locality: {subject_info.get('localityName', '')}")
            console.print(f"Email: {subject_info.get('emailAddress', '')}")

            # Certificate details
            console.print(f"Serial: {info['serial']}")
            console.print(f"Valid From: {info['not_before']}")
            console.print(f"Valid Until: {info['not_after']}")

            # Format days remaining with color based on how soon it expires
            days_remaining = info["days_remaining"]
            if days_remaining < 0:
                console.print(
                    f"Days Remaining: [bold red]{days_remaining} (expired)[/bold red]"
                )
            elif days_remaining < EXPIRY_CRITICAL_DAYS:
                console.print(f"Days Remaining: [bold red]{days_remaining}[/bold red]")
            elif days_remaining < EXPIRY_WARNING_DAYS:
                console.print(
                    f"Days Remaining: [bold yellow]{days_remaining}[/bold yellow]"
                )
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
@click.pass_context
def host(ctx: click.Context) -> None:
    """Host certificate operations."""
    pass


@host.command(name="issue")
@click.argument("hostname", required=False)
@click.option(
    "--all", "all_hosts", is_flag=True, help="Issue certificates for all hosts"
)
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
@click.pass_context
def host_issue(
    ctx: click.Context,
    hostname: str | None,
    all_hosts: bool,
    no_export: bool,
    deploy: bool,
) -> None:
    """Create or renew certificates for hosts."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    if hostname and all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Cannot specify both hostname and --all"
        )
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Must specify either hostname or --all"
        )
        ctx.exit(1)

    if all_hosts:
        # Issue certificates for all hosts
        result = issue_all_certificates(
            config, store, no_export=no_export, do_deploy=deploy
        )

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
        result = issue_certificate(
            hostname, config, store, no_export=no_export, do_deploy=deploy
        )

        if isinstance(result, Success):
            info = result.unwrap()
            action = "created" if info["is_new"] else "renewed"

            console.print(
                f"✅ Certificate {action} successfully for [bold]{hostname}[/bold]"
            )
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
            if info["is_new"]:
                console.print(
                    f"   Private key (encrypted): [bold]{info['key_path']}[/bold]"
                )

            if "export" in info:
                export_info = info["export"]
                if "cert" in export_info:
                    console.print(
                        f"✅ Certificate exported to [bold]{export_info['cert']}[/bold]"
                    )
                if "chain" in export_info:
                    console.print(
                        f"✅ Certificate chain exported to [bold]{export_info['chain']}[/bold]"
                    )

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
@click.option(
    "--key",
    required=True,
    type=click.Path(exists=True),
    help="Path to private key file",
)
@click.pass_context
def host_import_key(ctx: click.Context, hostname: str, key: str) -> None:
    """Import an existing key for a host."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

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
def host_export_key(ctx: click.Context, hostname: str, out: str | None = None) -> None:
    """Export unencrypted private key for a host."""
    # Initialize config and store with unlock
    _, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    # Export host key
    result = export_host_key_unencrypted(hostname, store, out)

    if isinstance(result, Success):
        info = result.unwrap()
        if "export_path" in info:
            console.print(
                f"✅ Unencrypted key exported to [bold]{info['export_path']}[/bold]"
            )
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
def host_rekey(
    ctx: click.Context,
    hostname: str | None,
    all_hosts: bool,
    no_export: bool,
    deploy: bool,
) -> None:
    """Generate new keys and certificates for hosts."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    if hostname and all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Cannot specify both hostname and --all"
        )
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Must specify either hostname or --all"
        )
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
        result = rekey_host(
            hostname, config, store, no_export=no_export, do_deploy=deploy
        )

        if isinstance(result, Success):
            info = result.unwrap()
            console.print(
                f"✅ Certificate and key rekeyed successfully for [bold]{hostname}[/bold]"
            )
            console.print(f"   Certificate: [bold]{info['cert_path']}[/bold]")
            console.print(
                f"   Private key (encrypted): [bold]{info['key_path']}[/bold]"
            )

            if "export" in info:
                export_info = info["export"]
                if "cert" in export_info:
                    console.print(
                        f"✅ Certificate exported to [bold]{export_info['cert']}[/bold]"
                    )
                if "chain" in export_info:
                    console.print(
                        f"✅ Certificate chain exported to [bold]{export_info['chain']}[/bold]"
                    )

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
def host_list(
    ctx: click.Context, expired: bool, expiring: int | None, json_output: bool
) -> None:
    """List certificates with their expiration dates."""
    # Initialize config and store with unlock
    _, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

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
            elif days_remaining < EXPIRY_CRITICAL_DAYS:
                days_formatted = f"[bold red]{days_remaining}[/bold red]"
            elif days_remaining < EXPIRY_WARNING_DAYS:
                days_formatted = f"[bold yellow]{days_remaining}[/bold yellow]"
            else:
                days_formatted = str(days_remaining)

            ca_table.add_row(
                ca_info["serial"],
                ca_info["not_after"],
                days_formatted,
                ca_info["fingerprint"],
            )

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
                elif days < EXPIRY_CRITICAL_DAYS:
                    days_str = f"[bold red]{days}[/bold red]"
                elif days < EXPIRY_WARNING_DAYS:
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
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    if hostname and all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Cannot specify both hostname and --all"
        )
        ctx.exit(1)

    if not hostname and not all_hosts:
        console.print(
            "[bold red]Error:[/bold red] Must specify either hostname or --all"
        )
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
            console.print(
                f"✅ Deployment completed successfully for [bold]{hostname}[/bold]"
            )
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
    # Initialize config and store with unlock (we need config to identify configured hosts)
    _config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

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
@click.option(
    "--csr", required=True, type=click.Path(exists=True), help="Path to the CSR file"
)
@click.option("--out", required=True, help="Output path for the signed certificate")
@click.option("--validity-days", type=int, default=None, help="Validity period in days")
@click.option(
    "--validity-years", type=int, default=None, help="Validity period in years"
)
@click.pass_context
def host_sign_csr(
    ctx: click.Context,
    csr: str,
    out: str,
    validity_days: int | None,
    validity_years: int | None,
) -> None:
    """Sign a CSR and output the certificate."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    # Calculate validity period
    if validity_days is not None and validity_years is not None:
        console.print(
            "[bold red]Error:[/bold red] Cannot specify both --validity-days and --validity-years"
        )
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
@click.pass_context
def util(ctx: click.Context) -> None:
    """Perform utility operations."""
    pass


@util.command(name="passwd")
@click.pass_context
def util_passwd(ctx: click.Context) -> None:
    """Change password for all encrypted keys."""
    # Initialize config and store with unlock
    config, store = init_config_and_store(ctx, "unlock")
    assert store is not None  # for type checking
    console = ctx.obj["console"]

    # Get new password
    console.print(
        "You will need to provide the current password and then the new password."
    )

    # Get new password
    if config.ca_config is None:
        console.print("[bold red]Error:[/bold red] No CA configuration found")
        ctx.exit(1)

    new_password_result = get_password(
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

    # Change passwords
    result = change_password(store, new_password)

    if isinstance(result, Success):
        console.print("✅ Password changed successfully for all keys")
    else:
        console.print(
            f"[bold red]Error:[/bold red] {result.error if isinstance(result, Failure) else 'Unknown error'}"
        )
        ctx.exit(1)


if __name__ == "__main__":
    cli()
