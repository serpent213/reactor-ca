"""Certificate export and deployment operations.

This module handles exporting certificates and private keys,
as well as running deployment commands for certificates.
"""

import logging
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from rich.console import Console

from reactor_ca.result import Failure, Result, Success

# Module-level console instance
CONSOLE = Console()

# Setup logging
logger = logging.getLogger(__name__)


def export_cert(cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a certificate to the specified path.

    Args:
    ----
        cert: Certificate to export
        export_path: Path to export certificate to

    Returns:
    -------
        Result with None or error message

    """
    try:
        # Ensure parent directory exists
        export_path.parent.mkdir(parents=True, exist_ok=True)

        # Write certificate to export path
        cert_bytes = cert.public_bytes(Encoding.PEM)
        with open(export_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Exported certificate to {export_path}")
        CONSOLE.print(f"✅ Certificate exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        error_msg = f"Failed to export certificate: {str(e)}"
        logger.error(error_msg)
        CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
        return Failure(error_msg)


def export_cert_chain(host_cert: x509.Certificate, ca_cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a certificate chain (host + CA certs) to the specified path.

    Args:
    ----
        host_cert: Host certificate
        ca_cert: CA certificate
        export_path: Path to export certificate chain to

    Returns:
    -------
        Result with None or error message

    """
    try:
        # Ensure parent directory exists
        export_path.parent.mkdir(parents=True, exist_ok=True)

        # Write host certificate followed by CA certificate
        host_cert_bytes = host_cert.public_bytes(Encoding.PEM)
        ca_cert_bytes = ca_cert.public_bytes(Encoding.PEM)

        with open(export_path, "wb") as f:
            f.write(host_cert_bytes)
            f.write(ca_cert_bytes)

        logger.info(f"Exported certificate chain to {export_path}")
        CONSOLE.print(f"✅ Certificate chain exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        error_msg = f"Failed to export certificate chain: {str(e)}"
        logger.error(error_msg)
        CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
        return Failure(error_msg)


def export_unencrypted_key(key: PrivateKeyTypes, export_path: Path) -> Result[None, str]:
    """Export an unencrypted private key to the specified path.

    Args:
    ----
        key: Private key
        export_path: Path to export key to

    Returns:
    -------
        Result with None or error message

    """
    try:
        # Ensure parent directory exists
        export_path.parent.mkdir(parents=True, exist_ok=True)

        # Write unencrypted key to export path
        key_bytes = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        with open(export_path, "wb") as f:
            f.write(key_bytes)

        logger.info(f"Exported unencrypted private key to {export_path}")
        CONSOLE.print(f"✅ Unencrypted private key exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        error_msg = f"Failed to export private key: {str(e)}"
        logger.error(error_msg)
        CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
        return Failure(error_msg)


def deploy(command: str, cert: x509.Certificate, key: PrivateKeyTypes) -> Result[None, str]:
    """Run a deployment command after certificate export.

    Args:
    ----
        command: The command to run
        cert: Certificate being deployed
        key: Private key being deployed

    Returns:
    -------
        Result with None or error message

    """
    try:
        # Run the command
        CONSOLE.print(f"Running deployment command: [bold]{command}[/bold]")
        logger.info(f"Running deployment command: {command}")

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )

        # Check if successful
        if result.returncode == 0:
            logger.info("Successfully ran deployment command")
            CONSOLE.print("✅ Deployment command executed successfully")
            return Success(None)
        else:
            error_msg = f"Deployment command failed (exit code {result.returncode}): {result.stderr}"
            logger.error(error_msg)
            CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
            return Failure(error_msg)
    except Exception as e:
        error_msg = f"Failed to run deployment command: {str(e)}"
        logger.error(error_msg)
        CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
        return Failure(error_msg)
