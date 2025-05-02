#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool."""

import os
import shutil
from pathlib import Path

import click

from reactor_ca import __version__
from reactor_ca.ca_operations import (
    import_ca,
    issue_ca,
    rekey_ca,
    show_ca_info,
)
from reactor_ca.config import Config, init_config_files, validate_config_files
from reactor_ca.crypto import (
    calculate_validity_days,
)
from reactor_ca.host_operations import (
    deploy_all_hosts,
    deploy_host,
    export_host_key,
    import_host_key,
    issue_all_certificates,
    issue_certificate,
    list_certificates,
    load_ca_key_cert,
    process_csr,
    rekey_all_hosts,
    rekey_host,
)
from reactor_ca.models import ValidityConfig
from reactor_ca.store import change_password, get_store
from reactor_ca.utils import (
    console,
)


@click.group()
@click.version_option(version=__version__)
@click.option("--config", type=click.Path(exists=False), help="Path to the configuration directory")
@click.option("--store", type=click.Path(exists=False), help="Path to the certificate store directory")
@click.option(
    "--root", type=click.Path(exists=False), help="Root directory (both config and store will be subdirectories)"
)
@click.pass_context
def cli(ctx: click.Context, config: str | None = None, store: str | None = None, root: str | None = None) -> None:
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    # Create Config and Store instances

    # Set environment variables for tests that change directories
    if root:
        os.environ["REACTOR_CA_ROOT"] = root
    if config:
        os.environ["REACTOR_CA_CONFIG_DIR"] = config
    if store:
        os.environ["REACTOR_CA_STORE_DIR"] = store

    # Create a configuration with specified paths or defaults
    # Note that we're passing absolute paths here to ensure they work correctly
    # even if the current directory changes
    app_config = Config.create(
        config_dir=os.path.abspath(config) if config else None,
        store_dir=os.path.abspath(store) if store else None,
        root_dir=os.path.abspath(root) if root else None,
    )

    # Store the config and store in the context for subcommands
    ctx.obj = {"config": app_config, "store": get_store(app_config)}

    # Ensure directories exist
    ctx.obj["store"].init()


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
    app_config = ctx.obj["config"]

    # Make sure the directory exists
    app_config.config_dir.mkdir(parents=True, exist_ok=True)

    init_config_files(app_config.ca_config_path, app_config.hosts_config_path, force)


@config.command(name="validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate configuration files against schemas."""
    app_config = ctx.obj["config"]

    # Using validate_configs with our Config paths
    valid = validate_config_files(app_config.ca_config_path, app_config.hosts_config_path)
    if not valid:
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
    store = ctx.obj["store"]
    issue_ca(store=store)


@ca.command(name="import")
@click.option("--cert", required=True, help="Path to CA certificate file")
@click.option("--key", required=True, help="Path to CA private key file")
@click.pass_context
def ca_import(ctx: click.Context, cert: str, key: str) -> None:
    """Import an existing CA."""
    store = ctx.obj["store"]
    import_ca(Path(cert), Path(key), store=store)


@ca.command(name="rekey")
@click.pass_context
def ca_rekey(ctx: click.Context) -> None:
    """Generate a new key and renew the CA certificate."""
    store = ctx.obj["store"]
    rekey_ca(store=store)


@ca.command(name="info")
@click.option("--json", is_flag=True, help="Output in JSON format")
@click.pass_context
def ca_info(ctx: click.Context, json: bool) -> None:
    """Show information about the CA."""
    store = ctx.obj["store"]
    show_ca_info(json_output=json, store=store)


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
def host_issue(hostname: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Create or renew certificates for hosts."""
    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        return

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        return

    if all_hosts:
        issue_all_certificates(no_export=no_export, do_deploy=deploy)
    else:
        # hostname is not None here because we checked earlier
        assert hostname is not None
        issue_certificate(hostname, no_export=no_export, do_deploy=deploy)


@host.command(name="import-key")
@click.argument("hostname", required=True)
@click.option("--key", required=True, help="Path to private key file")
def host_import_key(hostname: str, key: str) -> None:
    """Import an existing key for a host."""
    import_host_key(hostname, key)


@host.command(name="export-key")
@click.argument("hostname", required=True)
@click.option("--out", help="Path to output file (stdout if not provided)")
def host_export_key(hostname: str, out: str | None) -> None:
    """Export unencrypted private key for a host."""
    export_host_key(hostname, out)


@host.command(name="rekey")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Rekey all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
def host_rekey(hostname: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Generate new keys and certificates for hosts."""
    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        return

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        return

    if all_hosts:
        rekey_all_hosts(no_export=no_export, do_deploy=deploy)
    else:
        # hostname is not None here because we checked earlier
        assert hostname is not None
        rekey_host(hostname, no_export=no_export, do_deploy=deploy)


@host.command(name="list")
@click.option("--expired", is_flag=True, help="Only show expired certificates")
@click.option("--expiring", type=int, help="Show certificates expiring within days")
@click.option("--json", is_flag=True, help="Output in JSON format")
def host_list(expired: bool, expiring: int | None, json: bool) -> None:
    """List certificates with their expiration dates."""
    list_certificates(expired=expired, expiring_days=expiring, json_output=json)


@host.command(name="deploy")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Deploy all hosts")
def host_deploy(hostname: str | None, all_hosts: bool) -> None:
    """Deploy certificates to configured destinations."""
    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        return

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        return

    store = get_store()
    if all_hosts:
        deploy_all_hosts()
    else:
        # hostname is not None here because we checked earlier
        assert hostname is not None
        deploy_host(store, hostname)


@host.command(name="clean")
def host_clean() -> None:
    """Remove host folders that are no longer in the configuration."""
    # Load the hosts configuration
    store = get_store()
    hosts_config = store.load_hosts_config()
    configured_hosts = [host["name"] for host in hosts_config.get("hosts", [])]

    hosts_dir = store.config.hosts_dir

    # Check if hosts_dir exists
    if not hosts_dir.exists():
        console.print("[bold yellow]Warning:[/bold yellow] No hosts directory found.")
        return

    # Get all host directories
    existing_host_dirs = [d for d in hosts_dir.iterdir() if d.is_dir()]

    # Find hosts that are no longer in the configuration
    hosts_to_remove = []
    for host_dir in existing_host_dirs:
        hostname = host_dir.name
        if hostname not in configured_hosts:
            hosts_to_remove.append(hostname)

    if not hosts_to_remove:
        console.print("✅ No obsolete host folders found.")
        return

    # Ask for confirmation for each host
    for hostname in hosts_to_remove:
        if click.confirm(f"Remove host folder for {hostname}?", default=True):
            host_dir = hosts_dir / hostname
            try:
                shutil.rmtree(host_dir)
                console.print(f"✅ Removed host folder for [bold]{hostname}[/bold]")
            except Exception as e:
                console.print(f"[bold red]Error removing host folder for {hostname}:[/bold red] {str(e)}")

    # Update inventory after cleaning
    console.print("Updating inventory...")
    store.update_inventory()
    console.print("✅ Inventory updated.")


@host.command(name="sign-csr")
@click.option("--csr", required=True, help="Path to the CSR file")
@click.option("--out", required=True, help="Output path for the signed certificate")
@click.option("--validity-days", type=int, default=None, help="Validity period in days")
@click.option("--validity-years", type=int, default=None, help="Validity period in years")
def host_sign_csr(csr: str, out: str, validity_days: int | None, validity_years: int | None) -> None:
    """Sign a CSR and output the certificate."""
    # Calculate validity period using utility function
    if validity_days is not None and validity_years is not None:
        console.print("[bold red]Error:[/bold red] Cannot specify both --validity-days and --validity-years")
        return

    validity_config = ValidityConfig(days=validity_days, years=validity_years)
    validity = calculate_validity_days(validity_config)

    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return

    hostname, cert = process_csr(csr, ca_key, ca_cert, validity_days=validity, out_path=out)
    if hostname and cert:
        console.print(f"✅ Successfully signed CSR for [bold]{hostname}[/bold]")


# Utility operations
@cli.group()
def util() -> None:
    """Perform utility operations."""
    pass


@util.command(name="passwd")
def util_passwd() -> None:
    """Change password for all encrypted keys."""
    store = get_store()
    change_password(store)


if __name__ == "__main__":
    cli()
