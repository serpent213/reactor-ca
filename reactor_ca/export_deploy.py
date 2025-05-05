"""Certificate export and deployment operations.

This module handles exporting certificates and private keys, 
as well as running deployment commands for certificates.
"""

import logging
import os
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding, 
    NoEncryption, 
    PrivateFormat
)
from rich.console import Console

from reactor_ca.result import Failure, Result, Success

# Module-level console instance
CONSOLE = Console()

# Setup logging
logger = logging.getLogger(__name__)


def export_ca_cert(cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export the CA certificate to the specified path.

    Args:
    ----
        cert: CA certificate
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

        logger.info(f"Exported CA certificate to {export_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export CA certificate: {str(e)}")


def export_host_cert(cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a host certificate to the specified path.

    Args:
    ----
        cert: Host certificate
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
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export certificate: {str(e)}")


def export_host_key_unencrypted(key: PrivateKeyTypes, export_path: Path) -> Result[None, str]:
    """Export an unencrypted host private key to the specified path.

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
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export private key: {str(e)}")


def export_host_chain(host_cert: x509.Certificate, ca_cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a host certificate chain (host + CA certs) to the specified path.

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
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export certificate chain: {str(e)}")


def run_deploy_command(command: str, hostname: str) -> Result[str, str]:
    """Run a deployment command after certificate export.

    Args:
    ----
        command: The command to run
        hostname: The hostname, used for environment variable substitution

    Returns:
    -------
        Result with command output or error message

    """
    try:
        # Set environment variables that might be useful
        env = os.environ.copy()
        env["HOSTNAME"] = hostname
        env["REACTOR_CA_CERT_HOST"] = hostname

        # Run the command
        CONSOLE.print(f"Running deployment command: {command}")
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        # Check if successful
        if result.returncode == 0:
            logger.info(f"Successfully ran deployment command for {hostname}")
            return Success(result.stdout)
        else:
            return Failure(
                f"Deployment command failed (exit code {result.returncode}): {result.stderr}"
            )
    except Exception as e:
        return Failure(f"Failed to run deployment command: {str(e)}")