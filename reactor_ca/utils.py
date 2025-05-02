"""Utility functions for ReactorCA."""

import os
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from rich.console import Console

from reactor_ca.store import Store

# Constants for expiration warnings
EXPIRY_CRITICAL = 30  # days
EXPIRY_WARNING = 90  # days

console = Console()


def format_certificate_expiry(days_remaining: int) -> str:
    """Format days remaining until certificate expiry with appropriate color coding.

    Args:
    ----
        days_remaining: Number of days until certificate expires

    Returns:
    -------
        Rich-formatted string with appropriate color coding

    """
    if days_remaining < 0:
        return f"[bold red]{days_remaining} (expired)[/bold red]"
    elif days_remaining < EXPIRY_CRITICAL:
        return f"[bold orange]{days_remaining}[/bold orange]"
    elif days_remaining < EXPIRY_WARNING:
        return f"[bold yellow]{days_remaining}[/bold yellow]"
    else:
        return f"{days_remaining}"


def write_private_key_to_temp_file(private_key: PrivateKeyTypes, hostname: str) -> tuple[str, list[str]]:
    """Write a private key to a temporary file with secure permissions.

    Args:
    ----
        private_key: The private key to write
        hostname: Hostname for prefix

    Returns:
    -------
        Tuple of (temp file path, list of all temp files created)

    """
    temp_files = []

    # Create a temporary file for the private key with restricted permissions
    fd, temp_key_path = tempfile.mkstemp(suffix=".key", prefix=f"{hostname}-")
    temp_files.append(temp_key_path)

    # Close the file descriptor
    os.close(fd)

    # Set secure permissions (600 - owner read/write only)
    os.chmod(temp_key_path, stat.S_IRUSR | stat.S_IWUSR)

    # Write the decrypted key to the temporary file
    with open(temp_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )

    return temp_key_path, temp_files


def get_host_paths(store: "Store", hostname: str) -> tuple[Path, Path, Path]:
    """Get paths for a host's certificate files.

    Args:
    ----
        store: Store instance
        hostname: The hostname for the certificate

    Returns:
    -------
        Tuple of (host_dir, cert_path, key_path)

    """
    host_dir = store.get_host_dir(hostname)
    cert_path = store.get_host_cert_path(hostname)
    key_path = store.get_host_key_path(hostname)
    return host_dir, cert_path, key_path


def run_deploy_command(store: "Store", hostname: str, command: str) -> bool:
    """Run a deployment command for a host.

    Args:
    ----
        store: Store instance
        hostname: The hostname for the certificate
        command: The command to run with variable substitution

    Returns:
    -------
        True if deployment was successful, False otherwise

    Supports variable substitution:
    - ${cert} - Path to the host certificate file
    - ${private_key} - Path to a temporary file containing the decrypted private key

    """
    if not command:
        return False

    try:
        temp_files = []
        modified_command = command

        # Get standard paths for this host
        host_dir, cert_path, key_path = get_host_paths(store, hostname)

        # Replace ${cert} with certificate path if it exists
        if "${cert}" in command and cert_path.exists():
            modified_command = modified_command.replace("${cert}", str(cert_path.absolute()))

        # Handle ${private_key} if it exists in the command
        if "${private_key}" in command and key_path.exists():
            # Get password
            if not store.is_unlocked:
                if not store.unlock():
                    console.print("[bold red]Error:[/bold red] Cannot decrypt private key - no password provided")
                    return False

            try:
                # Load the private key
                private_key = store.load_host_key(hostname)
                if not private_key:
                    console.print(f"[bold red]Error:[/bold red] Failed to load private key for {hostname}")
                    return False

                # Write key to temporary file
                temp_key_path, created_temp_files = write_private_key_to_temp_file(private_key, hostname)
                temp_files.extend(created_temp_files)

                # Replace the variable in the command
                modified_command = modified_command.replace("${private_key}", temp_key_path)

            except Exception as e:
                console.print(f"[bold red]Error preparing private key for {hostname}:[/bold red] {str(e)}")
                # Clean up any temporary files created so far
                for temp_file in temp_files:
                    try:
                        os.unlink(temp_file)
                    except Exception as ie:
                        console.print(f"[bold red]Error removing temp file:[/bold red] {str(ie)}")
                return False

        # Run the modified command
        console.print(f"Running deployment command for [bold]{hostname}[/bold]: {modified_command}")
        result = os.system(modified_command)

        # Clean up any temporary files
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except Exception as e:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Could not delete temporary file {temp_file}: {str(e)}"
                )

        if result == 0:
            console.print(f"✅ Deployment for [bold]{hostname}[/bold] completed successfully")
            return True
        else:
            console.print(f"[bold red]Deployment for {hostname} failed with exit code {result}[/bold red]")
            return False
    except Exception as e:
        console.print(f"[bold red]Error during deployment for {hostname}:[/bold red] {str(e)}")
        return False
