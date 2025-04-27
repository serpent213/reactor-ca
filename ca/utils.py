"""Utility functions for ReactorCA."""

import datetime
import sys
from pathlib import Path

import click
import git
import yaml
from rich.console import Console

console = Console()

# Global password cache
_password_cache = None


def ensure_dirs():
    """Ensure all required directories exist."""
    dirs = ["config", "certs/ca", "certs/hosts"]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)


def create_default_config():
    """Create default configuration files."""
    ca_config = {
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
            "validity_days": 3650,
            "password": {
                "min_length": 12,
                "storage": "session",  # "none", "session", "keyring"
            },
        }
    }

    hosts_config = {
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
                "destination": "../path/to/deploy/cert/server1.pem",
                "validity_days": 365,
                "key": {
                    "algorithm": "RSA",
                    "size": 2048,
                },
            },
        ]
    }

    # Create config directory if it doesn't exist
    Path("config").mkdir(exist_ok=True)

    # Write CA config
    ca_config_path = Path("config/ca_config.yaml")
    with open(ca_config_path, "w") as f:
        yaml.dump(ca_config, f, default_flow_style=False, sort_keys=False)

    # Write hosts config
    hosts_config_path = Path("config/hosts.yaml")
    with open(hosts_config_path, "w") as f:
        yaml.dump(hosts_config, f, default_flow_style=False, sort_keys=False)

    console.print("✅ Created default configuration files:")
    console.print(f"  CA config: [bold]{ca_config_path}[/bold]")
    console.print(f"  Hosts config: [bold]{hosts_config_path}[/bold]")
    console.print("Please review and customize these files before initializing the CA.")


def load_config():
    """Load CA configuration."""
    config_path = Path("config/ca_config.yaml")

    if not config_path.exists():
        console.print(f"[bold red]Error:[/bold red] Configuration file not found: {config_path}")
        console.print("Run with --init to create a default configuration.")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        return config
    except Exception as e:
        console.print(f"[bold red]Error loading configuration:[/bold red] {str(e)}")
        sys.exit(1)


def load_hosts_config():
    """Load hosts configuration."""
    hosts_path = Path("config/hosts.yaml")

    if not hosts_path.exists():
        console.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {hosts_path}")
        return {"hosts": []}

    try:
        with open(hosts_path, "r") as f:
            hosts_config = yaml.safe_load(f)

        return hosts_config
    except Exception as e:
        console.print(f"[bold red]Error loading hosts configuration:[/bold red] {str(e)}")
        return {"hosts": []}


def get_password():
    """Get password for key encryption/decryption, with optional caching."""
    global _password_cache

    # Load config to check password storage setting
    config = load_config()
    storage_mode = config["ca"]["password"]["storage"]
    min_length = config["ca"]["password"]["min_length"]

    # If password is already cached and storage is set to session, return it
    if storage_mode == "session" and _password_cache:
        return _password_cache

    # Prompt for password
    password = click.prompt(
        "Enter password for key encryption/decryption",
        hide_input=True,
        confirmation_prompt=False,
    )

    # Validate password length
    if len(password) < min_length:
        console.print(
            f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long"
        )
        return None

    # Cache password if configured to do so
    if storage_mode == "session":
        _password_cache = password

    return password


def save_inventory(inventory):
    """Save certificate inventory."""
    inventory_path = Path("inventory.yaml")

    try:
        with open(inventory_path, "w") as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        console.print(f"[bold red]Error saving inventory:[/bold red] {str(e)}")


def load_inventory():
    """Load certificate inventory."""
    inventory_path = Path("inventory.yaml")

    if not inventory_path.exists():
        # Create empty inventory
        inventory = {
            "last_update": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ca": {},
            "hosts": [],
        }
        save_inventory(inventory)
        return inventory

    try:
        with open(inventory_path, "r") as f:
            inventory = yaml.safe_load(f)

        return inventory
    except Exception as e:
        console.print(f"[bold red]Error loading inventory:[/bold red] {str(e)}")
        # Return empty inventory as fallback
        return {
            "last_update": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ca": {},
            "hosts": [],
        }


def scan_cert_files():
    """Scan certificate files and update inventory."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    inventory = load_inventory()
    ca_dir = Path("certs/ca")
    hosts_dir = Path("certs/hosts")

    # Update timestamp for comparison
    last_update = datetime.datetime.fromisoformat(inventory.get("last_update", "1970-01-01T00:00:00+00:00"))

    # Check CA certificate
    ca_cert_path = ca_dir / "ca.crt"
    if ca_cert_path.exists():
        # Check if file is newer than last update
        mod_time = datetime.datetime.fromtimestamp(ca_cert_path.stat().st_mtime, tz=datetime.timezone.utc)

        if mod_time > last_update:
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
                # Check if file is newer than last update
                mod_time = datetime.datetime.fromtimestamp(cert_path.stat().st_mtime, tz=datetime.timezone.utc)

                if mod_time > last_update:
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
                            inventory.setdefault("hosts", []).append({
                                "name": hostname,
                                "serial": format(cert.serial_number, "x"),
                                "not_after": cert.not_valid_after.isoformat(),
                                "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                                "renewal_count": 0,
                            })
                    except Exception as e:
                        console.print(
                            f"[bold red]Error loading certificate for {hostname}:[/bold red] {str(e)}"
                        )

    # Update last_update timestamp
    inventory["last_update"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Save updated inventory
    save_inventory(inventory)

    return inventory


def update_inventory():
    """Update inventory based on certificate files."""
    return scan_cert_files()


def commit_changes():
    """Commit all changes to Git."""
    try:
        # Check if git repo exists
        repo_path = Path(".")
        try:
            repo = git.Repo(repo_path)
        except git.exc.InvalidGitRepositoryError:
            console.print("[bold red]Error:[/bold red] Not a Git repository")
            if click.confirm("Initialize a new Git repository?"):
                repo = git.Repo.init(repo_path)
            else:
                return

        # Check for changes
        changed = [item.a_path for item in repo.index.diff(None)]
        staged = [item.a_path for item in repo.index.diff("HEAD")]
        untracked = repo.untracked_files

        if not (changed or staged or untracked):
            console.print("No changes to commit")
            return

        console.print("Changes to commit:")
        for path in changed:
            console.print(f"  Modified: {path}")
        for path in untracked:
            console.print(f"  Untracked: {path}")

        # Add files
        files_to_add = []

        # Add or update .gitignore if needed
        gitignore_path = Path(".gitignore")

        if not gitignore_path.exists():
            # Create .gitignore file with private keys excluded
            with open(gitignore_path, "w") as f:
                f.write("# Ignore encrypted private keys\n")
                f.write("**/*.key\n")
                f.write("**/*.key.enc\n")
                f.write("# Python artifacts\n")
                f.write("__pycache__/\n")
                f.write("*.py[cod]\n")
                f.write("*$py.class\n")
                f.write("*.so\n")
                f.write(".Python\n")
                f.write("env/\n")
                f.write(".env\n")
                f.write(".venv\n")
                f.write(".pytest_cache/\n")

            files_to_add.append(".gitignore")

        # Add configuration files
        if Path("config").exists():
            for file in Path("config").glob("*.yaml"):
                files_to_add.append(str(file))

        # Add certificates (but not private keys)
        if Path("certs").exists():
            for cert_file in Path("certs").glob("**/*.crt"):
                files_to_add.append(str(cert_file))

        # Add inventory
        if Path("inventory.yaml").exists():
            files_to_add.append("inventory.yaml")

        # Add Python source files
        for py_file in Path(".").glob("**/*.py"):
            if ".venv" not in str(py_file):
                files_to_add.append(str(py_file))

        # Add files
        for file in files_to_add:
            try:
                repo.git.add(file)
                console.print(f"Added {file}")
            except git.exc.GitCommandError as e:
                console.print(f"[bold red]Error adding {file}:[/bold red] {str(e)}")

        # Commit
        if click.confirm("Commit changes?"):
            message = click.prompt("Enter commit message", default="Update certificates")
            repo.git.commit("-m", message)
            console.print(f"✅ Changes committed with message: [bold]{message}[/bold]")
        else:
            console.print("Commit cancelled")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")


def change_password():
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
        console.print(
            f"[bold red]Error:[/bold red] Password must be at least {min_length} characters long"
        )
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

    # Update password cache if we're using session storage
    global _password_cache
    if config["ca"]["password"]["storage"] == "session":
        _password_cache = new_password

    # Summary
    console.print(f"\n✅ Changed password for {success_count} key files")
    if error_count > 0:
        console.print(f"❌ Failed to change password for {error_count} key files")
