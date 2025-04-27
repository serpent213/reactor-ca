#!/usr/bin/env python3
"""Main CLI entry point for the ReactorCA tool."""

import click
from rich.console import Console

from ca import __version__
from ca.ca_operations import import_key, initialize_ca
from ca.cert_operations import (
    generate_certificate,
    list_certificates,
    process_csr_file,
    renew_all_certificates,
    renew_certificate,
)
from ca.utils import change_password, commit_changes, ensure_dirs

console = Console()

@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx):
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    # Create necessary directories if they don't exist
    ensure_dirs()

    # If no command is supplied, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
def init():
    """Initialize a new CA with a self-signed certificate."""
    initialize_ca()


@cli.command()
@click.argument("hostname")
def generate(hostname):
    """Generate a new certificate for a host."""
    generate_certificate(hostname)


@cli.command()
@click.argument("hostname")
def renew(hostname):
    """Renew a certificate for a host."""
    renew_certificate(hostname)


@cli.command()
def renew_all():
    """Renew all certificates."""
    renew_all_certificates()


@cli.command()
def list():
    """List all certificates with their expiration dates."""
    list_certificates()


@cli.command()
def commit():
    """Commit all changes to Git."""
    commit_changes()


@cli.command()
def passwd():
    """Change password for all encrypted keys."""
    change_password()


@cli.command()
@click.option("--type", type=click.Choice(["ca", "host"]), required=True, help="Type of key to import")
@click.option("--hostname", help="Hostname for host key")
@click.option("--key-path", required=True, help="Path to the key file to import")
@click.option("--cert-path", help="Path to the certificate file to import")
def import_key_cmd(type, hostname, key_path, cert_path):
    """Import an existing private key and optionally a certificate."""
    if type == "host" and not hostname:
        raise click.BadParameter("Hostname is required for host key import")

    import_key(type, hostname, key_path, cert_path)


@cli.command()
@click.argument("csr_path")
def process_csr(csr_path):
    """Process a Certificate Signing Request file."""
    process_csr_file(csr_path)


if __name__ == "__main__":
    cli()
