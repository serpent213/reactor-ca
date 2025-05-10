"""Certificate export and deployment operations.

This module handles exporting certificates and private keys,
as well as running deployment commands for certificates.
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from rich.console import Console

from reactor_ca.result import Failure, Result, Success, is_failure, is_success
from reactor_ca.store import read_host_key
from reactor_ca.x509_crypto import deserialize_private_key

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


def export_host_key_unencrypted_from_store(
    hostname: str, store_path: str, password: str, out_path: str | None = None
) -> Result[dict[str, Any], str]:
    """Export an unencrypted private key for a host from the store.

    Args:
    ----
        hostname: Hostname for the key
        store_path: Path to the certificate store
        out_path: Path to save the unencrypted key (if None, return key data in result)
        password: Optional password for decrypting the key

    Returns:
    -------
        Result with key info dict or error message

    """
    # Load host key
    key_result = read_host_key(store_path, hostname, password)
    if is_failure(key_result):
        return Failure(f"Failed to load host key: {key_result.error}")

    # Safe to unwrap because we checked for failure
    key_data = cast(Success[bytes], key_result).value
    # Safely deserialize the private key
    private_key_result = deserialize_private_key(key_data, password.encode() if password else None)
    if is_failure(private_key_result):
        return Failure(f"Failed to deserialize private key: {private_key_result.error}")

    # Safe to unwrap because we checked for failure
    private_key = cast(Success[PrivateKeyTypes], private_key_result).value

    # Export unencrypted key
    if out_path:
        export_path = Path(out_path)
        export_result = export_host_key_unencrypted(private_key, export_path)
        if is_failure(export_result):
            return Failure(f"Failed to export key: {export_result.error}")

        return Success({"action": "exported_key", "hostname": hostname, "export_path": str(export_path)})
    else:
        # Return key data in result
        unencrypted_key_data = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        return Success({"action": "exported_key", "hostname": hostname, "key_data": unencrypted_key_data.decode()})


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
            return Failure(f"Deployment command failed (exit code {result.returncode}): {result.stderr}")
    except Exception as e:
        return Failure(f"Failed to run deployment command: {str(e)}")


def deploy_host(hostname: str, store_path: str, hosts_config: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Run the deployment script for a host.

    Args:
    ----
        hostname: Hostname to deploy
        store_path: Path to the certificate store
        hosts_config: Loaded hosts configuration

    Returns:
    -------
        Result with deployment info dict or error message

    """
    # Find host config
    host_config = None
    for host in hosts_config.get("hosts", []):
        if host.get("name") == hostname:
            host_config = host
            break

    if not host_config:
        return Failure(f"Host {hostname} not found in hosts configuration")

    # Check if deployment is configured
    if "deploy" not in host_config or "command" not in host_config["deploy"]:
        return Failure(f"No deployment command configured for {hostname}")

    # Run deployment command
    deploy_command = host_config["deploy"]["command"]
    deploy_result = run_deploy_command(deploy_command, hostname)
    if is_failure(deploy_result):
        return Failure(f"Deployment failed: {deploy_result.error}")

    return Success(
        {
            "action": "deployed",
            "hostname": hostname,
            "command": deploy_command,
            "output": cast(Success[str], deploy_result).value,
        }
    )


def deploy_all_hosts(store_path: str, hosts_config: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Deploy all host certificates.

    Args:
    ----
        store_path: Path to the certificate store
        hosts_config: Loaded hosts configuration

    Returns:
    -------
        Result with deployment info dict or error message

    """
    hosts = [host.get("name") for host in hosts_config.get("hosts", [])]
    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0
    results = {}

    for hostname in hosts:
        deploy_result = deploy_host(hostname, store_path, hosts_config)

        if is_success(deploy_result):
            success_count += 1
            results[hostname] = cast(Success[dict[str, Any]], deploy_result).value
        else:
            error_count += 1
            results[hostname] = {"error": cast(Failure[str], deploy_result).error}

    return Success(
        {
            "action": "batch_deploy",
            "total": len(hosts),
            "success": success_count,
            "error": error_count,
            "results": results,
        }
    )
