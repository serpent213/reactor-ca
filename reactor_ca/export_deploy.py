"""Certificate export and deployment operations.

This module handles exporting certificates and private keys,
as well as running deployment commands for certificates.
"""

import logging
import os
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from rich.console import Console

from reactor_ca.paths import get_host_cert_path
from reactor_ca.result import Failure, Result, Success
from reactor_ca.x509_crypto import serialize_certificate, serialize_private_key

# Module-level console instance
CONSOLE = Console()
logger = logging.getLogger(__name__)


def export_cert(cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a certificate to the specified path."""
    try:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        cert_bytes_res = serialize_certificate(cert)
        if isinstance(cert_bytes_res, Failure):
            return cert_bytes_res
        export_path.write_bytes(cert_bytes_res.unwrap())
        logger.info(f"Exported certificate to {export_path}")
        CONSOLE.print(f"✅ Certificate exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        return _log_and_fail(f"Failed to export certificate: {e!s}")


def export_cert_chain(host_cert: x509.Certificate, ca_cert: x509.Certificate, export_path: Path) -> Result[None, str]:
    """Export a certificate chain (host + CA certs) to the specified path."""
    try:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        host_bytes_res = serialize_certificate(host_cert)
        if isinstance(host_bytes_res, Failure):
            return host_bytes_res
        ca_bytes_res = serialize_certificate(ca_cert)
        if isinstance(ca_bytes_res, Failure):
            return ca_bytes_res
        export_path.write_bytes(host_bytes_res.unwrap() + ca_bytes_res.unwrap())
        logger.info(f"Exported certificate chain to {export_path}")
        CONSOLE.print(f"✅ Certificate chain exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        return _log_and_fail(f"Failed to export certificate chain: {e!s}")


def export_unencrypted_key(key: PrivateKeyTypes, export_path: Path) -> Result[None, str]:
    """Export an unencrypted private key to the specified path."""
    try:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        key_bytes_res = serialize_private_key(key, password=None)
        if isinstance(key_bytes_res, Failure):
            return key_bytes_res
        export_path.write_bytes(key_bytes_res.unwrap())
        logger.info(f"Exported unencrypted private key to {export_path}")
        CONSOLE.print(f"✅ Unencrypted private key exported to [bold]{export_path}[/bold]")
        return Success(None)
    except Exception as e:
        return _log_and_fail(f"Failed to export private key: {e!s}")


def deploy(command: str, cert: x509.Certificate, key: PrivateKeyTypes) -> Result[None, str]:
    """Run a deployment command after certificate export. Replaces ${cert} and ${private_key}.

    Args:
    ----
        command: The command to run.
        cert: Certificate being deployed.
        key: Private key being deployed.

    Returns:
    -------
        Result with None or error message.

    """
    temp_key_path = None
    try:
        # Prepare command with substitutions
        modified_command = command
        if "${cert}" in command:
            cert_path = get_host_cert_path(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
            modified_command = modified_command.replace("${cert}", str(cert_path.absolute()))

        if "${private_key}" in command:
            temp_key_path = _write_key_to_temp_file(key).unwrap()
            modified_command = modified_command.replace("${private_key}", temp_key_path)

        # Securely execute the command
        logger.info(f"Running deployment command: {modified_command}")
        CONSOLE.print(f"Running deployment command: [bold]{modified_command}[/bold]")

        # Use shlex.split to avoid command injection
        args = shlex.split(modified_command)
        result = subprocess.run(args, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            logger.info("Successfully ran deployment command")
            if result.stdout:
                logger.info(f"Deploy stdout: {result.stdout.strip()}")
            return Success(None)
        return _log_and_fail(f"Deployment command failed (exit code {result.returncode}): {result.stderr.strip()}")

    except Exception as e:
        return _log_and_fail(f"Failed to run deployment command: {e!s}")
    finally:
        # Ensure temporary key file is deleted
        if temp_key_path:
            try:
                os.unlink(temp_key_path)
            except OSError as e:
                logger.warning(f"Failed to delete temporary key file {temp_key_path}: {e!s}")


def _write_key_to_temp_file(key: PrivateKeyTypes) -> Result[str, str]:
    """Write a private key to a temporary file with secure permissions."""
    try:
        key_bytes_res = serialize_private_key(key, password=None)
        if isinstance(key_bytes_res, Failure):
            return key_bytes_res

        fd, temp_path = tempfile.mkstemp(suffix=".key", prefix="reactor-ca-")
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions
        with os.fdopen(fd, "wb") as f:
            f.write(key_bytes_res.unwrap())
        return Success(temp_path)
    except Exception as e:
        return Failure(f"Failed to create temporary key file: {e!s}")


def _log_and_fail(error_msg: str) -> Failure[str]:
    """Logs an error and returns a Failure object."""
    logger.error(error_msg)
    CONSOLE.print(f"[bold red]Error:[/bold red] {error_msg}")
    return Failure(error_msg)
