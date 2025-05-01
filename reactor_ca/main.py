#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool."""

from pathlib import Path

import click

from reactor_ca import __version__
from reactor_ca.ca_operations import (
    import_ca,
    issue_ca,
    rekey_ca,
    show_ca_info,
)
from reactor_ca.cert_operations import (
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
from reactor_ca.config_validator import validate_configs
from reactor_ca.utils import (
    calculate_validity_days,
    change_password,
    console,
    create_default_config,
    ensure_dirs,
)


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    # Create necessary directories if they don't exist
    ensure_dirs()


# Configuration commands
@cli.group()
def config() -> None:
    """Manage configuration files."""
    pass


@config.command(name="init")
def config_init() -> None:
    """Initialize configuration files."""
    create_default_config()


@config.command(name="validate")
def config_validate() -> None:
    """Validate configuration files against schemas."""
    validate_configs()


# CA management commands
@cli.group()
def ca() -> None:
    """Certificate Authority management commands."""
    pass


@ca.command(name="issue")
def ca_issue() -> None:
    """Create or renew a CA certificate."""
    issue_ca()


@ca.command(name="help")
@click.pass_context
def ca_help(ctx: click.Context) -> None:
    """Show help information for CA commands."""
    # Display the same help as 'ca --help' would show
    if ctx.parent is not None:
        click.echo(ctx.parent.get_help())
    else:
        click.echo(ca.get_help(ctx))


@ca.command(name="import")
@click.option("--cert", required=True, help="Path to CA certificate file")
@click.option("--key", required=True, help="Path to CA private key file")
def ca_import(cert: str, key: str) -> None:
    """Import an existing CA."""
    import_ca(Path(cert), Path(key))


@ca.command(name="rekey")
def ca_rekey() -> None:
    """Generate a new key and renew the CA certificate."""
    rekey_ca()


@ca.command(name="info")
@click.option("--json", is_flag=True, help="Output in JSON format")
def ca_info(json: bool) -> None:
    """Show information about the CA."""
    show_ca_info(json_output=json)


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

    if all_hosts:
        deploy_all_hosts()
    else:
        # hostname is not None here because we checked earlier
        assert hostname is not None
        deploy_host(hostname)


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

    validity_config = {}
    if validity_days is not None:
        validity_config["days"] = validity_days
    elif validity_years is not None:
        validity_config["years"] = validity_years

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
    change_password()


if __name__ == "__main__":
    cli()
