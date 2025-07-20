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

from reactor_ca import __version__
from reactor_ca.cli_ca import get_ca_info, get_ca_info_dict, import_ca, issue_ca, rekey_ca
from reactor_ca.cli_host import (
    clean_certificates,
    deploy_all_hosts,
    deploy_host,
    get_certificates_list_dict,
    issue_all_certificates,
    issue_certificate,
    list_certificates,
    process_csr,
    rekey_all_hosts,
    rekey_host,
)
from reactor_ca.cli_host import export_host_key_unencrypted_wrapper as export_host_key_unencrypted
from reactor_ca.cli_host import import_host_key as import_host_key_func
from reactor_ca.config import create as create_config
from reactor_ca.config import init as init_config
from reactor_ca.config import validate as validate_config
from reactor_ca.models import CAConfig, Config, Store, ValidityConfig
from reactor_ca.password import get_password
from reactor_ca.paths import get_log_path, resolve_paths
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import change_password
from reactor_ca.store import create as create_store
from reactor_ca.store import init as init_store


def _setup_logging(store_path: Path) -> None:
    """Initializes logging for the application."""
    logging.basicConfig(
        filename=get_log_path(store_path),
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _get_password_from_config(ctx: click.Context, ca_config: CAConfig, confirm: bool) -> str:
    """Gets the master password, handling prompt, env var, or file."""
    console = ctx.obj["console"]
    password_result = get_password(
        min_length=ca_config.password.min_length,
        password_file=ca_config.password.file,
        env_var=ca_config.password.env_var,
        prompt_message="Enter CA master password: ",
        confirm=confirm,
    )
    if isinstance(password_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {password_result.error}")
        ctx.exit(1)
    return password_result.unwrap()


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

    config_dir, store_dir = resolve_paths(root_path, config_path, store_path)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["store_dir"] = store_dir

    # Eagerly initialize and store the config and store objects
    # This makes them available to all subcommands.
    console = ctx.obj["console"]

    config_result = init_config(config_dir)
    if isinstance(config_result, Failure):
        # Allow `config init` to run without a pre-existing config
        if not (ctx.invoked_subcommand == "config" and ctx.args[0] == "init"):
            console.print(f"[bold red]Error:[/bold red] {config_result.error}")
            console.print('Run "ca config init" to initialize the configuration.')
            ctx.exit(1)
        ctx.obj["config"] = None
    else:
        ctx.obj["config"] = config_result.value

    store_result = init_store(store_dir)
    if isinstance(store_result, Failure):
        if not (ctx.invoked_subcommand == "config" and ctx.args[0] == "init"):
            console.print(f"[bold red]Error:[/bold red] {store_result.error}")
            console.print('Run "ca config init" to initialize the store.')
            ctx.exit(1)
        ctx.obj["store"] = None
    else:
        ctx.obj["store"] = store_result.value
        _setup_logging(store_dir)


# Configuration commands
@cli.group()
def config() -> None:
    """Manage configuration files."""


@config.command(name="init")
@click.option("--force", is_flag=True, help="Force overwrite of existing config files")
@click.pass_context
def config_init(ctx: click.Context, force: bool) -> None:
    """Initialize configuration files."""
    console = ctx.obj["console"]
    config_path = Path(ctx.obj["config_dir"])
    store_path = Path(ctx.obj["store_dir"])

    config_result = create_config(config_path, force=force)
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

    result = validate_config(config_path)
    if isinstance(result, Failure):
        ctx.exit(1)
    console.print("✅ All configuration files are valid")


# CA management commands
@cli.group()
def ca() -> None:
    """Certificate Authority management commands."""


@ca.command(name="create")
@click.pass_context
def ca_create(ctx: click.Context) -> None:
    """Create or renew a CA certificate."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store or not config.ca_config:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    password = _get_password_from_config(ctx, config.ca_config, confirm=True)
    result = issue_ca(ctx, config, store, password)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@ca.command(name="import")
@click.option(
    "--cert",
    "cert_path_str",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to CA certificate file",
)
@click.option(
    "--key",
    "key_path_str",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to CA private key file",
)
@click.option("--key-password", help="Password for the source key file")
@click.pass_context
def ca_import(ctx: click.Context, cert_path_str: Path, key_path_str: Path, key_password: str | None) -> None:
    """Import an existing CA."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store or not config.ca_config:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    new_password = _get_password_from_config(ctx, config.ca_config, confirm=True)
    result = import_ca(ctx, cert_path_str, key_path_str, config, store, new_password, key_password)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@ca.command(name="rekey")
@click.pass_context
def ca_rekey(ctx: click.Context) -> None:
    """Generate a new key and renew the CA certificate."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store or not config.ca_config:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    password = _get_password_from_config(ctx, config.ca_config, confirm=False)
    result = rekey_ca(ctx, config, store, password)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@ca.command(name="info")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.pass_context
def ca_info(ctx: click.Context, json_output: bool) -> None:
    """Show information about the Certificate Authority."""
    console = ctx.obj["console"]
    store: Store = ctx.obj["store"]
    if not store:
        console.print("[bold red]Error:[/bold red] Store not initialized.")
        ctx.exit(1)

    if json_output:
        result = get_ca_info_dict(store)
        if isinstance(result, Success):
            console.print(json.dumps(result.unwrap(), indent=2))
        else:
            console.print(f"[bold red]Error:[/bold red] {result.error}")
            ctx.exit(1)
    else:
        display_result: Result[None, str] = get_ca_info(ctx, store)
        if isinstance(display_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {display_result.error}")
            ctx.exit(1)


# Host certificate operations
@cli.group()
def host() -> None:
    """Host certificate operations."""


def _get_deps_for_host_op(ctx: click.Context) -> tuple[Config, Store, str]:
    """Helper to get Config, Store, and Password for host operations."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store or not config.ca_config:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    password = _get_password_from_config(ctx, config.ca_config, confirm=False)
    return config, store, password


@host.command(name="issue")
@click.argument("hostname", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Issue certificates for all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
@click.pass_context
def host_issue(ctx: click.Context, hostname: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Create or renew certificates for hosts."""
    console = ctx.obj["console"]
    config, store, password = _get_deps_for_host_op(ctx)

    if hostname and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both hostname and --all")
        ctx.exit(1)
    if not hostname and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either hostname or --all")
        ctx.exit(1)

    if all_hosts:
        result = issue_all_certificates(ctx, config, store, password, no_export=no_export, do_deploy=deploy)
    else:
        assert hostname is not None
        result = issue_certificate(ctx, hostname, config, store, password, no_export=no_export, do_deploy=deploy)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="import-key")
@click.argument("host_id", required=True)
@click.option(
    "--key", "key_path_str", required=True, type=click.Path(exists=True, path_type=Path), help="Path to private key"
)
@click.pass_context
def host_import_key(ctx: click.Context, host_id: str, key_path_str: Path) -> None:
    """Import an existing key for a host."""
    console = ctx.obj["console"]
    config, store, password = _get_deps_for_host_op(ctx)
    result = import_host_key_func(ctx, host_id, key_path_str, config, store, password)
    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="export-key")
@click.argument("host_id", required=True)
@click.option("--out", help="Path to output file (stdout if not provided)")
@click.pass_context
def host_export_key(ctx: click.Context, host_id: str, out: str | None = None) -> None:
    """Export unencrypted private key for a host."""
    console = ctx.obj["console"]
    _, store, password = _get_deps_for_host_op(ctx)
    result = export_host_key_unencrypted(ctx, host_id, store, password, out)
    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="rekey")
@click.argument("host_id", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Rekey all hosts")
@click.option("--no-export", is_flag=True, help="Skip export of certificates")
@click.option("--deploy", is_flag=True, help="Deploy certificates after export")
@click.pass_context
def host_rekey(ctx: click.Context, host_id: str | None, all_hosts: bool, no_export: bool, deploy: bool) -> None:
    """Generate new keys and certificates for hosts."""
    console = ctx.obj["console"]
    config, store, password = _get_deps_for_host_op(ctx)

    if host_id and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both host_id and --all")
        ctx.exit(1)
    if not host_id and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either host_id or --all")
        ctx.exit(1)

    if all_hosts:
        result = rekey_all_hosts(ctx, config, store, password, no_export=no_export, do_deploy=deploy)
    else:
        assert host_id is not None
        result = rekey_host(ctx, host_id, config, store, password, no_export=no_export, do_deploy=deploy)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="list")
@click.option("--expired", is_flag=True, help="Only show expired certificates")
@click.option("--expiring", type=int, help="Show certificates expiring within days")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.pass_context
def host_list(ctx: click.Context, expired: bool, expiring: int | None, json_output: bool) -> None:
    """List certificates with their expiration dates."""
    console = ctx.obj["console"]
    store: Store = ctx.obj["store"]
    if not store:
        console.print("[bold red]Error:[/bold red] Store not initialized.")
        ctx.exit(1)

    if json_output:
        result = get_certificates_list_dict(store, expired=expired, expiring_days=expiring)
        if isinstance(result, Success):
            console.print(json.dumps(result.unwrap(), indent=2))
        else:
            console.print(f"[bold red]Error:[/bold red] {result.error}")
            ctx.exit(1)
    else:
        display_result: Result[None, str] = list_certificates(ctx, store, expired=expired, expiring_days=expiring)
        if isinstance(display_result, Failure):
            console.print(f"[bold red]Error:[/bold red] {display_result.error}")
            ctx.exit(1)


@host.command(name="deploy")
@click.argument("host_id", required=False)
@click.option("--all", "all_hosts", is_flag=True, help="Deploy all hosts")
@click.pass_context
def host_deploy(ctx: click.Context, host_id: str | None, all_hosts: bool) -> None:
    """Deploy certificates to configured destinations."""
    console = ctx.obj["console"]
    config, store, password = _get_deps_for_host_op(ctx)

    if host_id and all_hosts:
        console.print("[bold red]Error:[/bold red] Cannot specify both host_id and --all")
        ctx.exit(1)
    if not host_id and not all_hosts:
        console.print("[bold red]Error:[/bold red] Must specify either host_id or --all")
        ctx.exit(1)

    if all_hosts:
        result = deploy_all_hosts(ctx, config, store, password)
    else:
        assert host_id is not None
        result = deploy_host(ctx, host_id, config, store, password)

    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="clean")
@click.pass_context
def host_clean(ctx: click.Context) -> None:
    """Remove host folders that are no longer in the configuration."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    result = clean_certificates(ctx, config, store)
    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


@host.command(name="sign-csr")
@click.option("--csr", "csr_path_str", required=True, type=click.Path(exists=True), help="Path to the CSR file")
@click.option("--out", "out_path_str", required=True, help="Output path for the signed certificate")
@click.option("--validity-days", type=int, default=None, help="Validity period in days")
@click.option("--validity-years", type=int, default=None, help="Validity period in years")
@click.pass_context
def host_sign_csr(
    ctx: click.Context,
    csr_path_str: str,
    out_path_str: str,
    validity_days: int | None,
    validity_years: int | None,
) -> None:
    """Sign a CSR and output the certificate."""
    console = ctx.obj["console"]
    config, store, password = _get_deps_for_host_op(ctx)

    if validity_days is not None and validity_years is not None:
        console.print("[bold red]Error:[/bold red] Cannot specify both --validity-days and --validity-years")
        ctx.exit(1)

    validity_config = ValidityConfig(days=validity_days, years=validity_years)
    validity_result = validity_config.to_days()
    if isinstance(validity_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {validity_result.error}")
        ctx.exit(1)
    validity = validity_result.unwrap()

    result = process_csr(ctx, csr_path_str, config, store, password, validity_days=validity, out_path=out_path_str)
    if isinstance(result, Failure):
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


# Utility operations
@cli.group()
def util() -> None:
    """Perform utility operations."""


@util.command(name="passwd")
@click.pass_context
def util_passwd(ctx: click.Context) -> None:
    """Change password for all encrypted keys."""
    console = ctx.obj["console"]
    config: Config = ctx.obj["config"]
    store: Store = ctx.obj["store"]
    if not config or not store or not config.ca_config:
        console.print("[bold red]Error:[/bold red] Configuration or store not initialized.")
        ctx.exit(1)

    console.print("You will need to provide the current password and then the new password.")
    old_password = _get_password_from_config(ctx, config.ca_config, confirm=False)

    new_password_result = get_password(
        min_length=config.ca_config.password.min_length,
        prompt_message="Enter new CA master password: ",
        confirm=True,
    )
    if isinstance(new_password_result, Failure):
        console.print(f"[bold red]Error:[/bold red] {new_password_result.error}")
        ctx.exit(1)
    new_password = new_password_result.unwrap()

    result = change_password(store, old_password, new_password)

    if isinstance(result, Success):
        console.print("✅ Password changed successfully for all keys")
    else:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)


if __name__ == "__main__":
    cli()
