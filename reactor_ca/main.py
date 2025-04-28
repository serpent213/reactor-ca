#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool."""

import click
from rich.console import Console

from reactor_ca import __version__
from reactor_ca.ca_operations import (
    create_ca,
    import_ca,
    rekey_ca,
    renew_ca_cert,
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
    process_csr,
    rekey_all_hosts,
    rekey_host,
)
from reactor_ca.utils import change_password, create_default_config, ensure_dirs
from reactor_ca.config_validator import validate_configs, validate_config_before_operation

console = Console()

@click.group()
@click.version_option(version=__version__)
def cli():
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    # Create necessary directories if they don't exist
    ensure_dirs()


# Configuration commands
@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command(name="init")
def config_init():
    """Initialize configuration files."""
    create_default_config()


@config.command(name="validate")
def config_validate():
    """Validate configuration files against schemas."""
    validate_configs()


# CA management commands
@cli.group()
def ca():
    """Certificate Authority management commands."""
    pass


@ca.command(name="create")
def ca_create():
    """Create a new CA."""
    create_ca()


@ca.command(name="import")
@click.option("--cert", required=True, help="Path to CA certificate file")
@click.option("--key", required=True, help="Path to CA private key file")
def ca_import(cert, key):
    """Import an existing CA."""
    import_ca(cert, key)


@ca.command(name="renew")
def ca_renew():
    """Renew the CA certificate using the existing key."""
    renew_ca_cert()


@ca.command(name="rekey")
def ca_rekey():
    """Generate a new key and renew the CA certificate."""
    rekey_ca()


@ca.command(name="info")
@click.option("--json", is_flag=True, help="Output in JSON format")
def ca_info(json):
    """Show information about the CA."""
    show_ca_info(json_output=json)


# Host certificate operations
@cli.group()
def host():
    """Host certificate operations."""
    pass


@host.command(name="issue")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Issue certificates for all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
def host_issue(hostname, all_hosts, no_export, deploy):
    """Issue or renew certificates for hosts."""
    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        return

    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        return

    if all_hosts:
        issue_all_certificates(no_export=no_export, do_deploy=deploy)
    else:
        issue_certificate(hostname, no_export=no_export, do_deploy=deploy)


@host.command(name="import")
@click.argument("hostname", required=True)
@click.option("--key", required=True, help="Path to private key file")
def host_import(hostname, key):
    """Import an existing key for a host."""
    import_host_key(hostname, key)


@host.command(name="export-key")
@click.argument("hostname", required=True)
@click.option("--out", help="Path to output file (stdout if not provided)")
def host_export_key(hostname, out):
    """Export unencrypted private key for a host."""
    export_host_key(hostname, out)


@host.command(name="rekey")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Rekey all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
def host_rekey(hostname, all_hosts, no_export, deploy):
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
        rekey_host(hostname, no_export=no_export, do_deploy=deploy)


@host.command(name="list")
@click.option("--expired", is_flag=True, help="Only show expired certificates")
@click.option("--expiring", type=int, help="Show certificates expiring within days")
@click.option("--json", is_flag=True, help="Output in JSON format")
def host_list(expired, expiring, json):
    """List certificates with their expiration dates."""
    list_certificates(expired=expired, expiring_days=expiring, json_output=json)


@host.command(name="deploy")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Deploy all hosts")
def host_deploy(hostname, all_hosts):
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
        deploy_host(hostname)


@host.command(name="sign-csr")
@click.option("--csr", required=True, help="Path to the CSR file")
@click.option("--out", required=True, help="Output path for the signed certificate")
@click.option("--validity", type=int, default=365, help="Validity period in days")
def host_sign_csr(csr, out, validity):
    """Sign a CSR and output the certificate."""
    from reactor_ca.ca_operations import load_ca_key_cert

    ca_key, ca_cert = load_ca_key_cert()
    if not ca_key or not ca_cert:
        return

    hostname, cert = process_csr(csr, ca_key, ca_cert, validity_days=validity, out_path=out)
    if hostname and cert:
        console.print(f"✅ Successfully signed CSR for [bold]{hostname}[/bold]")


# Utility operations
@cli.group()
def util():
    """Utility operations."""
    pass


@util.command(name="passwd")
def util_passwd():
    """Change password for all encrypted keys."""
    change_password()


if __name__ == "__main__":
    cli()
