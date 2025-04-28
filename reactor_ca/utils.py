"""Utility functions for ReactorCA."""

import datetime
import os
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console

console = Console()

# Module-level cache for password
# Using a list as a container to avoid global statement warnings when modifying
_password_cache_container: list[str | None] = [None]


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    dirs = ["config", "certs/ca", "certs/hosts"]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def calculate_validity_days(validity_config: dict[str, int]) -> int:
    """Calculate validity period in days based on the configuration."""
    if "days" in validity_config:
        return validity_config["days"]
    elif "years" in validity_config:
        return validity_config["years"] * 365
    else:
        # Default to 1 year if neither is specified
        return 365


def create_default_config() -> None:
    """Create default configuration files."""
    ca_config: dict[str, Any] = {
        "ca": {
            "common_name": "Reactor CA",
            "organization": "Reactor Homelab",
            "organization_unit": "IT",
            "country": "DE",
            "state": "Berlin",
            "locality": "Berlin",
            "email": "admin@example.com",
            "key": {
                "algorithm": "RSA",
                "size": 4096,
            },
            "validity": {
                "years": 10,
            },
            "password": {
                "min_length": 12,
                # Session caching is always enabled
                "file": "",  # Path to password file
                "env_var": "REACTOR_CA_PASSWORD",  # Environment variable for password
            },
        }
    }

    hosts_config: dict[str, Any] = {
        "hosts": [
            {
                "name": "server1.example.com",
                "common_name": "server1.example.com",
                "alternative_names": {
                    "dns": [
                        "www.example.com",
                        "api.example.com",
                    ],
                    "ip": [
                        "192.168.1.10",
                    ],
                },
                "export": {
                    "cert": "../path/to/export/cert/server1.pem",
                    "chain": "../path/to/export/cert/server1-chain.pem",  # Optional full chain
                },
                "deploy": {
                    "command": "systemctl reload nginx",  # Optional deployment command
                },
                "validity": {
                    "years": 1,
                },
                "key": {
                    "algorithm": "RSA",
                    "size": 2048,
                },
            },
        ]
    }

    # Create config directory if it doesn't exist
    Path("config").mkdir(exist_ok=True)

    # Write CA config with header comment
    ca_config_path = Path("config/ca_config.yaml")
    with open(ca_config_path, "w") as f:
        f.write("# ReactorCA Configuration\n")
        f.write("# This file contains settings for the Certificate Authority\n")
        f.write("# It is safe to modify this file directly\n\n")
        yaml.dump(ca_config, f, default_flow_style=False, sort_keys=False)

    # Write hosts config with header comment
    hosts_config_path = Path("config/hosts.yaml")
    with open(hosts_config_path, "w") as f:
        f.write("# ReactorCA Hosts Configuration\n")
        f.write("# This file contains settings for host certificates\n")
        f.write("# It is safe to modify this file directly\n\n")
        yaml.dump(hosts_config, f, default_flow_style=False, sort_keys=False)

    console.print("✅ Created default configuration files:")
    console.print(f"  CA config: [bold]{ca_config_path}[/bold]")
    console.print(f"  Hosts config: [bold]{hosts_config_path}[/bold]")
    console.print("Please review and customize these files before initializing the CA.")


def load_config() -> dict[str, Any]:
    """Load CA configuration."""
    config_path = Path("config/ca_config.yaml")

    if not config_path.exists():
        console.print(f"[bold red]Error:[/bold red] Configuration file not found: {config_path}")
        console.print("Run 'ca config init' to create a default configuration.")
        sys.exit(1)  # This exits the program

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            console.print("[bold red]Error:[/bold red] Invalid configuration format")
            sys.exit(1)  # This exits the program

        return config
    except Exception as e:
        console.print(f"[bold red]Error loading configuration:[/bold red] {str(e)}")
        sys.exit(1)  # This exits the program

    # For type checker only - this is never reached
    # mypy doesn't understand that sys.exit prevents execution from continuing
    raise AssertionError("Unreachable code")


def load_hosts_config() -> dict[str, Any]:
    """Load hosts configuration."""
    hosts_path = Path("config/hosts.yaml")

    if not hosts_path.exists():
        console.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {hosts_path}")
        return {"hosts": []}

    try:
        with open(hosts_path) as f:
            hosts_config = yaml.safe_load(f)

        if not isinstance(hosts_config, dict):
            console.print("[bold red]Error:[/bold red] Invalid hosts configuration format")
            return {"hosts": []}

        return hosts_config
    except Exception as e:
        console.print(f"[bold red]Error loading hosts configuration:[/bold red] {str(e)}")
        return {"hosts": []}  # Return empty hosts list as fallback


def read_password_from_file(password_file: str) -> str | None:
    """Read password from a file."""
    try:
        with open(password_file) as f:
            return f.read().strip()
    except Exception as e:
        console.print(f"[bold red]Error reading password file:[/bold red] {str(e)}")
        return None


def get_password() -> str | None:
    """Get password for key encryption/decryption, with multiple sources."""
    # Load config to check password settings
    config = load_config()
    min_length = config["ca"]["password"]["min_length"]
    password_file = config["ca"]["password"].get("file", "")
    env_var = config["ca"]["password"].get("env_var", "")

    # If password is already cached, return it
    if _password_cache_container[0]:
        return _password_cache_container[0]

    # Try to get the password from a file
    if password_file:
        password = read_password_from_file(password_file)
        if password and len(password) >= min_length:
            _password_cache_container[0] = password
            return password

    # Try to get the password from an environment variable
    if env_var and env_var in os.environ:
        password = os.environ[env_var]
        if password and len(password) >= min_length:
            _password_cache_container[0] = password
            return password

    # If we still don't have a password, prompt the user
    password = click.prompt(
        "Enter password for key encryption/decryption",
        hide_input=True,
        confirmation_prompt=False,
    )

    # Validate password length
    if password and len(password) < min_length:
        console.print(f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long")
        return None

    # Cache password for session
    _password_cache_container[0] = password

    return password


def save_inventory(inventory: dict[str, Any]) -> None:
    """Save certificate inventory."""
    inventory_path = Path("inventory.yaml")

    try:
        with open(inventory_path, "w") as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        console.print(f"[bold red]Error saving inventory:[/bold red] {str(e)}")


def load_inventory() -> dict[str, Any]:
    """Load certificate inventory."""
    inventory_path = Path("inventory.yaml")

    if not inventory_path.exists():
        # Create empty inventory
        inventory = {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {},
            "hosts": [],
        }
        save_inventory(inventory)
        return inventory

    try:
        with open(inventory_path) as f:
            inventory = yaml.safe_load(f)

        return inventory
    except Exception as e:
        console.print(f"[bold red]Error loading inventory:[/bold red] {str(e)}")
        # Return empty inventory as fallback
        return {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {},
            "hosts": [],
        }


def scan_cert_files() -> dict[str, Any]:
    """Scan certificate files and update inventory."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    inventory = load_inventory()
    ca_dir = Path("certs/ca")
    hosts_dir = Path("certs/hosts")

    # Check CA certificate
    ca_cert_path = ca_dir / "ca.crt"
    if ca_cert_path.exists():
        try:
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            inventory["ca"] = {
                "serial": format(ca_cert.serial_number, "x"),
                "not_after": ca_cert.not_valid_after.isoformat(),
                "fingerprint": "SHA256:" + ca_cert.fingerprint(hashes.SHA256()).hex(),
            }
        except Exception as e:
            console.print(f"[bold red]Error loading CA certificate:[/bold red] {str(e)}")

    # Check host certificates
    if hosts_dir.exists():
        host_dirs = [d for d in hosts_dir.iterdir() if d.is_dir()]

        for host_dir in host_dirs:
            hostname = host_dir.name
            cert_path = host_dir / "cert.crt"

            if cert_path.exists():
                try:
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())

                    # Find existing host entry or create new one
                    for host in inventory.setdefault("hosts", []):
                        if host["name"] == hostname:
                            host["serial"] = format(cert.serial_number, "x")
                            host["not_after"] = cert.not_valid_after.isoformat()
                            host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
                            # Keep renewal count if exists
                            break
                    else:
                        # Add new entry if not found
                        inventory.setdefault("hosts", []).append(
                            {
                                "name": hostname,
                                "serial": format(cert.serial_number, "x"),
                                "not_after": cert.not_valid_after.isoformat(),
                                "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                                "renewal_count": 0,
                            }
                        )
                except Exception as e:
                    console.print(f"[bold red]Error loading certificate for {hostname}:[/bold red] {str(e)}")

    # Update last_update timestamp
    inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()

    # Save updated inventory
    save_inventory(inventory)

    return inventory


def update_inventory() -> dict[str, Any]:
    """Update inventory based on certificate files."""
    return scan_cert_files()


def change_password() -> None:
    """Change password for all encrypted keys."""
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        load_pem_private_key,
    )

    # Get old password
    old_password = click.prompt(
        "Enter current password",
        hide_input=True,
        confirmation_prompt=False,
    )

    # Get new password with confirmation
    new_password = click.prompt(
        "Enter new password",
        hide_input=True,
        confirmation_prompt=True,
    )

    # Load config to check password requirements
    config = load_config()
    min_length = config["ca"]["password"]["min_length"]

    # Validate new password length
    if len(new_password) < min_length:
        console.print(f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long")
        return

    # Find all encrypted key files
    key_files = []

    # CA key
    ca_key_path = Path("certs/ca/ca.key.enc")
    if ca_key_path.exists():
        key_files.append(ca_key_path)

    # Host keys
    hosts_dir = Path("certs/hosts")
    if hosts_dir.exists():
        for host_dir in [d for d in hosts_dir.iterdir() if d.is_dir()]:
            key_path = host_dir / "cert.key.enc"
            if key_path.exists():
                key_files.append(key_path)

    if not key_files:
        console.print("[bold yellow]Warning:[/bold yellow] No encrypted key files found")
        return

    # Process each key file
    success_count = 0
    error_count = 0

    for key_path in key_files:
        try:
            # Read encrypted key
            with open(key_path, "rb") as f:
                encrypted_key_data = f.read()

            # Decrypt with old password
            try:
                private_key = load_pem_private_key(
                    encrypted_key_data,
                    password=old_password.encode(),
                )
            except Exception as e:
                console.print(f"[bold red]Error decrypting {key_path}:[/bold red] {str(e)}")
                error_count += 1
                continue

            # Re-encrypt with new password
            new_encrypted_data = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(new_password.encode()),
            )

            # Write updated key
            with open(key_path, "wb") as f:
                f.write(new_encrypted_data)

            success_count += 1
            console.print(f"✅ Re-encrypted {key_path}")

        except Exception as e:
            console.print(f"[bold red]Error processing {key_path}:[/bold red] {str(e)}")
            error_count += 1

    # Update password cache for session
    _password_cache_container[0] = new_password

    # Summary
    console.print(f"\n✅ Changed password for {success_count} key files")
    if error_count > 0:
        console.print(f"❌ Failed to change password for {error_count} key files")


def run_deploy_command(hostname: str, command: str) -> bool:
    """Run a deployment command for a host."""
    if not command:
        return False

    try:
        console.print(f"Running deployment command for [bold]{hostname}[/bold]...")
        result = os.system(command)

        if result == 0:
            console.print(f"✅ Deployment for [bold]{hostname}[/bold] completed successfully")
            return True
        else:
            console.print(f"[bold red]Deployment for {hostname} failed with exit code {result}[/bold red]")
            return False
    except Exception as e:
        console.print(f"[bold red]Error during deployment for {hostname}:[/bold red] {str(e)}")
        return False
