"""Host certificate operations for ReactorCA.

This module provides high-level functions for managing host certificates
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    NoEncryption,
    PrivateFormat,
    Encoding,
    load_pem_private_key,
)
from cryptography.x509.general_name import DirectoryName, OtherName, RegisteredID, UniformResourceIdentifier
from cryptography.x509.oid import NameOID

from reactor_ca.ca import load_ca_key_cert
from reactor_ca.config import load_ca_config, load_hosts_config, validate_yaml, validate_config_files, get_host_config
from reactor_ca.export_deploy import (
    export_host_cert,
    export_host_key_unencrypted,
    export_host_key_unencrypted_from_store,
    export_host_chain,
    run_deploy_command,
    deploy_host as export_deploy_host,
    deploy_all_hosts as export_deploy_all_hosts,
)
from reactor_ca.inventory import (
    read_inventory,
    update_inventory_with_host_cert,
    get_host_info as inventory_get_host_info,
    list_hosts_from_inventory,
)
from reactor_ca.models import (
    AlternativeNames,
    CertificateParams,
    HostConfig,
    SubjectIdentity,
    ValidityConfig,
)
from reactor_ca.password import get_password
from reactor_ca.result import Result, Success, Failure
from reactor_ca.store import (
    read_host_cert,
    read_host_key,
    write_host_cert,
    write_host_key,
    host_exists,
    list_hosts as store_list_hosts,
    delete_host,
)
from reactor_ca.paths import (
    get_host_cert_path,
    get_host_key_path,
)
from reactor_ca.x509_crypto import (
    generate_key,
    get_hash_algorithm,
    create_certificate,
    verify_key_algorithm,
    deserialize_certificate,
    deserialize_private_key,
)


def _load_configs(store_path: str) -> Result[tuple[CAConfig, dict[str, Any]], str]:
    """Load and validate CA and hosts configurations.

    Args:
    ----
        store_path: Path to the certificate store

    Returns:
    -------
        Result with tuple of (CAConfig, hosts_config) or error message
    """
    ca_config_path = Path(store_path) / "config" / "ca.yaml"
    hosts_config_path = Path(store_path) / "config" / "hosts.yaml"

    # Validate configs first
    validation_result = validate_config_files(ca_config_path, hosts_config_path)
    if not validation_result:
        return Failure(validation_result.error)

    # Load CA config
    ca_config_result = load_ca_config(ca_config_path)
    if not ca_config_result:
        return Failure(f"Failed to load CA configuration: {ca_config_result.error}")

    # Load hosts config
    hosts_config_result = load_hosts_config(hosts_config_path)
    if not hosts_config_result:
        return Failure(f"Failed to load hosts configuration: {hosts_config_result.error}")

    return Success((ca_config_result.unwrap(), hosts_config_result.unwrap()))


def _get_password_from_ca_config(store_path: str, password: Optional[str] = None) -> Result[str, str]:
    """Get password from CA config or from the provided password.

    Args:
    ----
        store_path: Path to the certificate store
        password: Optional password to use instead of config-based password

    Returns:
    -------
        Result with password string or error message
    """
    if password is not None:
        return Success(password)

    # Try to load CA config for password settings
    ca_config_path = Path(store_path) / "config" / "ca.yaml"

    try:
        ca_config_result = load_ca_config(ca_config_path)
        if not ca_config_result:
            # If can't load config, use defaults
            password_result = get_password(
                min_length=8,
                env_var="REACTOR_CA_PASSWORD",
                prompt_message="Enter CA master password: ",
                confirm=False,
            )
        else:
            ca_config = ca_config_result.unwrap()
            password_result = get_password(
                min_length=ca_config.password.min_length,
                password_file=ca_config.password.file if ca_config.password.file else None,
                env_var=ca_config.password.env_var if ca_config.password.env_var else None,
                prompt_message="Enter CA master password: ",
                confirm=False,
            )
    except Exception:
        # If can't load config, use defaults
        password_result = get_password(
            min_length=8,
            env_var="REACTOR_CA_PASSWORD",
            prompt_message="Enter CA master password: ",
            confirm=False,
        )

    if not password_result:
        return Failure(f"Failed to get password: {password_result.error}")

    return Success(password_result.unwrap())


def issue_certificate(
    hostname: str, store_path: str, password: Optional[str] = None, no_export: bool = False, do_deploy: bool = False
) -> Result[Dict[str, Any], str]:
    """Issue or renew a certificate for a host.

    Args:
    ----
        hostname: Hostname for the certificate
        store_path: Path to the certificate store
        password: Optional password for key encryption
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message
    """
    # Load and validate configurations
    configs_result = _load_configs(store_path)
    if not configs_result:
        return Failure(configs_result.error)

    ca_config, hosts_config = configs_result.unwrap()

    # Get password
    password_result = _get_password_from_ca_config(store_path, password)
    if not password_result:
        return Failure(password_result.error)
    password = password_result.unwrap()

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store_path, password)
    if not ca_result:
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Find host config
    host_config = None
    for host in hosts_config.get("hosts", []):
        if host.get("name") == hostname:
            host_config = host
            break

    if not host_config:
        return Failure(f"Host {hostname} not found in hosts configuration")

    # Check if certificate and key exist
    key_algorithm = host_config.get("key_algorithm", "RSA2048")
    is_new = not host_exists(store_path, hostname)

    # Handle key creation or loading
    private_key = None

    if is_new:
        # Create new key
        key_result = generate_key(key_algorithm)
        if not key_result:
            return Failure(f"Failed to generate key: {key_result.error}")
        private_key = key_result.unwrap()

        # Get password if not provided
        if password is None:
            # Try to get from CA config first
            try:
                ca_config = load_ca_config(ca_config_path)
                password_result = get_password(
                    min_length=ca_config.password.min_length,
                    password_file=ca_config.password.file if ca_config.password.file else None,
                    env_var=ca_config.password.env_var if ca_config.password.env_var else None,
                    prompt_message="Enter CA master password: ",
                    confirm=False,
                )
            except Exception:
                # If can't load config, use defaults
                password_result = get_password(
                    min_length=8,
                    env_var="REACTOR_CA_PASSWORD",
                    prompt_message="Enter CA master password: ",
                    confirm=False,
                )

            if not password_result:
                return Failure(f"Failed to get password: {password_result.error}")
            password = password_result.unwrap()
    else:
        # Use existing key
        # Get password if not provided
        if password is None:
            # Try to get from CA config first
            try:
                ca_config = load_ca_config(ca_config_path)
                password_result = get_password(
                    min_length=ca_config.password.min_length,
                    password_file=ca_config.password.file if ca_config.password.file else None,
                    env_var=ca_config.password.env_var if ca_config.password.env_var else None,
                    prompt_message="Enter CA master password: ",
                    confirm=False,
                )
            except Exception:
                # If can't load config, use defaults
                password_result = get_password(
                    min_length=8,
                    env_var="REACTOR_CA_PASSWORD",
                    prompt_message="Enter CA master password: ",
                    confirm=False,
                )

            if not password_result:
                return Failure(f"Failed to get password: {password_result.error}")
            password = password_result.unwrap()

        # Load existing key
        key_result = read_host_key(store_path, hostname, password)
        if not key_result:
            return Failure(f"Failed to load host key: {key_result.error}")

        key_data = key_result.unwrap()
        private_key_result = deserialize_private_key(key_data, password.encode() if password else None)
        if not private_key_result:
            return Failure(f"Failed to deserialize private key: {private_key_result.error}")

        private_key = private_key_result.unwrap()

        # Verify key algorithm
        key_algorithm_result = verify_key_algorithm(private_key, key_algorithm)
        if not key_algorithm_result:
            return Failure(f"Key algorithm mismatch. To use a new algorithm, please use rekey_host instead.")

    # Get validity period and prepare alternative names
    validity_config = host_config.get("validity", {})
    validity_days = ValidityConfig(days=validity_config.get("days"), years=validity_config.get("years")).to_days()

    alt_names = None
    if "alternative_names" in host_config:
        alt_names = AlternativeNames()
        for name_type, names in host_config["alternative_names"].items():
            if hasattr(alt_names, name_type) and names:
                setattr(alt_names, name_type, names)

    # Create host config object for certificate creation
    common_name = host_config.get("common_name", hostname)
    host_config_obj = HostConfig(
        name=hostname,
        common_name=common_name,
        organization=host_config.get("organization"),
        organization_unit=host_config.get("organization_unit"),
        country=host_config.get("country"),
        state=host_config.get("state"),
        locality=host_config.get("locality"),
        email=host_config.get("email"),
        alternative_names=alt_names,
        validity=ValidityConfig(days=validity_days),
        key_algorithm=key_algorithm,
        hash_algorithm=host_config.get("hash_algorithm"),
    )

    # Create certificate
    hash_algorithm = host_config_obj.hash_algorithm
    cert_params = CertificateParams(
        hostname=common_name,
        private_key=private_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=hash_algorithm,
        host_config=host_config_obj,
    )

    cert_result = create_certificate(cert_params)
    if not cert_result:
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_host_cert(store_path, hostname, cert_bytes)
    if not cert_save_result:
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    if is_new:
        key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        key_save_result = write_host_key(store_path, hostname, key_bytes, password)
        if not key_save_result:
            return Failure(f"Failed to save host key: {key_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store_path))
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()
    update_result = update_inventory_with_host_cert(
        Path(store_path), hostname, cert, inventory, rekeyed=False, renewal_count_increment=0 if is_new else 1
    )
    if not update_result:
        return Failure(f"Failed to update inventory: {update_result.error}")

    # Export certificate if requested
    export_info = {}
    if not no_export and "export" in host_config:
        export_config = host_config["export"]

        if "cert" in export_config:
            cert_path = Path(export_config["cert"])
            cert_result = export_host_cert(cert, cert_path)
            if cert_result:
                export_info["cert"] = str(cert_path)

        if "chain" in export_config:
            chain_path = Path(export_config["chain"])
            chain_result = export_host_chain(cert, ca_cert, chain_path)
            if chain_result:
                export_info["chain"] = str(chain_path)

    # Deploy if requested
    deploy_info = {}
    if do_deploy and "deploy" in host_config:
        deploy_command = host_config["deploy"].get("command")
        if deploy_command:
            deploy_result = run_deploy_command(deploy_command, hostname)
            if deploy_result:
                deploy_info["command"] = deploy_command
                deploy_info["output"] = deploy_result.unwrap()

    # Prepare result info
    result_info = {
        "action": "created" if is_new else "renewed",
        "hostname": hostname,
        "common_name": common_name,
        "cert_path": str(get_host_cert_path(Path(store_path), hostname)),
        "key_path": str(get_host_key_path(Path(store_path), hostname)),
        "validity_days": validity_days,
        "is_new": is_new,
    }

    if export_info:
        result_info["export"] = export_info
    if deploy_info:
        result_info["deploy"] = deploy_info

    return Success(result_info)


def issue_all_certificates(
    store_path: str, password: Optional[str] = None, no_export: bool = False, do_deploy: bool = False
) -> Result[Dict[str, Any], str]:
    """Issue or renew certificates for all hosts in configuration.

    Args:
    ----
        store_path: Path to the certificate store
        password: Optional password for key encryption
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message
    """
    # Load hosts configuration
    hosts_config_path = Path(store_path) / "config" / "hosts.yaml"

    try:
        hosts_config = load_hosts_config(hosts_config_path)
    except Exception as e:
        return Failure(f"Failed to load hosts configuration: {str(e)}")

    hosts = [host.get("name") for host in hosts_config.get("hosts", [])]
    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0
    results = {}

    for hostname in hosts:
        cert_result = issue_certificate(hostname, store_path, password, no_export, do_deploy)

        if cert_result:
            success_count += 1
            results[hostname] = cert_result.unwrap()
        else:
            error_count += 1
            results[hostname] = {"error": cert_result.error}

    return Success(
        {
            "action": "batch_issue",
            "total": len(hosts),
            "success": success_count,
            "error": error_count,
            "results": results,
        }
    )


def rekey_host(
    hostname: str, store_path: str, password: Optional[str] = None, no_export: bool = False, do_deploy: bool = False
) -> Result[Dict[str, Any], str]:
    """Generate a new key and certificate for a host.

    Args:
    ----
        hostname: Hostname for the certificate
        store_path: Path to the certificate store
        password: Optional password for key encryption
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message
    """
    # Load and validate configurations
    configs_result = _load_configs(store_path)
    if not configs_result:
        return Failure(configs_result.error)

    ca_config, hosts_config = configs_result.unwrap()

    # Get password
    password_result = _get_password_from_ca_config(store_path, password)
    if not password_result:
        return Failure(password_result.error)
    password = password_result.unwrap()

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store_path, password)
    if not ca_result:
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Find host config
    host_config = None
    for host in hosts_config.get("hosts", []):
        if host.get("name") == hostname:
            host_config = host
            break

    if not host_config:
        return Failure(f"Host {hostname} not found in hosts configuration")

    # Get key algorithm from config
    key_algorithm = host_config.get("key_algorithm", "RSA2048")

    # Create new key
    key_result = generate_key(key_algorithm)
    if not key_result:
        return Failure(f"Failed to generate key: {key_result.error}")
    private_key = key_result.unwrap()

    # Get validity period and prepare alternative names
    validity_config = host_config.get("validity", {})
    validity_days = ValidityConfig(days=validity_config.get("days"), years=validity_config.get("years")).to_days()

    alt_names = None
    if "alternative_names" in host_config:
        alt_names = AlternativeNames()
        for name_type, names in host_config["alternative_names"].items():
            if hasattr(alt_names, name_type) and names:
                setattr(alt_names, name_type, names)

    # Create host config object for certificate creation
    common_name = host_config.get("common_name", hostname)
    host_config_obj = HostConfig(
        name=hostname,
        common_name=common_name,
        organization=host_config.get("organization"),
        organization_unit=host_config.get("organization_unit"),
        country=host_config.get("country"),
        state=host_config.get("state"),
        locality=host_config.get("locality"),
        email=host_config.get("email"),
        alternative_names=alt_names,
        validity=ValidityConfig(days=validity_days),
        key_algorithm=key_algorithm,
        hash_algorithm=host_config.get("hash_algorithm"),
    )

    # Create certificate
    hash_algorithm = host_config_obj.hash_algorithm
    cert_params = CertificateParams(
        hostname=common_name,
        private_key=private_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=hash_algorithm,
        host_config=host_config_obj,
    )

    cert_result = create_certificate(cert_params)
    if not cert_result:
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_host_cert(store_path, hostname, cert_bytes)
    if not cert_save_result:
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    key_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_host_key(store_path, hostname, key_bytes, password)
    if not key_save_result:
        return Failure(f"Failed to save host key: {key_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store_path))
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()
    update_result = update_inventory_with_host_cert(
        Path(store_path), hostname, cert, inventory, rekeyed=True, renewal_count_increment=1
    )
    if not update_result:
        return Failure(f"Failed to update inventory: {update_result.error}")

    # Export certificate if requested
    export_info = {}
    if not no_export and "export" in host_config:
        export_config = host_config["export"]

        if "cert" in export_config:
            cert_path = Path(export_config["cert"])
            cert_result = export_host_cert(cert, cert_path)
            if cert_result:
                export_info["cert"] = str(cert_path)

        if "chain" in export_config:
            chain_path = Path(export_config["chain"])
            chain_result = export_host_chain(cert, ca_cert, chain_path)
            if chain_result:
                export_info["chain"] = str(chain_path)

    # Deploy if requested
    deploy_info = {}
    if do_deploy and "deploy" in host_config:
        deploy_command = host_config["deploy"].get("command")
        if deploy_command:
            deploy_result = run_deploy_command(deploy_command, hostname)
            if deploy_result:
                deploy_info["command"] = deploy_command
                deploy_info["output"] = deploy_result.unwrap()

    # Prepare result info
    result_info = {
        "action": "rekeyed",
        "hostname": hostname,
        "common_name": common_name,
        "cert_path": str(get_host_cert_path(Path(store_path), hostname)),
        "key_path": str(get_host_key_path(Path(store_path), hostname)),
        "validity_days": validity_days,
    }

    if export_info:
        result_info["export"] = export_info
    if deploy_info:
        result_info["deploy"] = deploy_info

    return Success(result_info)


def rekey_all_hosts(
    store_path: str, password: Optional[str] = None, no_export: bool = False, do_deploy: bool = False
) -> Result[Dict[str, Any], str]:
    """Rekey all hosts in configuration.

    Args:
    ----
        store_path: Path to the certificate store
        password: Optional password for key encryption
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message
    """
    # Load hosts configuration
    hosts_config_path = Path(store_path) / "config" / "hosts.yaml"

    try:
        hosts_config = load_hosts_config(hosts_config_path)
    except Exception as e:
        return Failure(f"Failed to load hosts configuration: {str(e)}")

    hosts = [host.get("name") for host in hosts_config.get("hosts", [])]
    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0
    results = {}

    for hostname in hosts:
        rekey_result = rekey_host(hostname, store_path, password, no_export, do_deploy)

        if rekey_result:
            success_count += 1
            results[hostname] = rekey_result.unwrap()
        else:
            error_count += 1
            results[hostname] = {"error": rekey_result.error}

    return Success(
        {
            "action": "batch_rekey",
            "total": len(hosts),
            "success": success_count,
            "error": error_count,
            "results": results,
        }
    )


def import_host_key(
    hostname: str, key_path: str, store_path: str, password: Optional[str] = None
) -> Result[Dict[str, Any], str]:
    """Import an existing private key for a host.

    Args:
    ----
        hostname: Hostname for the key
        key_path: Path to the key file to import
        store_path: Path to the certificate store
        password: Optional password for decrypting the source key

    Returns:
    -------
        Result with key info dict or error message
    """
    # Check if source key file exists
    src_key_path = Path(key_path)
    if not src_key_path.exists():
        return Failure(f"Key file not found: {key_path}")

    # Check if host already has a key
    if host_exists(store_path, hostname):
        return Failure(
            f"Certificate or key for {hostname} already exists. Remove it first or use a different hostname."
        )

    # Get password using our helper function
    password_result = _get_password_from_ca_config(store_path, password)
    if not password_result:
        return Failure(password_result.error)
    store_password = password_result.unwrap()

    # Load the key
    try:
        with open(src_key_path, "rb") as f:
            key_data = f.read()

        # Try to load it without password first
        src_password = None
        try:
            private_key_result = deserialize_private_key(key_data, None)
            if not private_key_result:
                # If deserialization fails, assume it's password-protected
                src_password_result = get_password(
                    min_length=4,  # Lower minimum for source key (we don't know the requirements)
                    prompt_message="Enter password for key to import: ",
                    confirm=False,
                )
                if not src_password_result:
                    return Failure(f"Failed to get source key password: {src_password_result.error}")
                src_password = src_password_result.unwrap()

                private_key_result = deserialize_private_key(key_data, src_password.encode())
                if not private_key_result:
                    return Failure(f"Failed to deserialize private key: {private_key_result.error}")
        except Exception as e:
            return Failure(f"Error loading key: {str(e)}")

        private_key = private_key_result.unwrap()
    except Exception as e:
        return Failure(f"Error loading key file: {str(e)}")

    # Save the key to the store
    key_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_host_key(store_path, hostname, key_bytes, store_password)
    if not key_save_result:
        return Failure(f"Failed to save host key: {key_save_result.error}")

    return Success(
        {
            "action": "imported_key",
            "hostname": hostname,
            "key_path": str(get_host_key_path(Path(store_path), hostname)),
            "source_path": str(src_key_path),
        }
    )


def export_host_key_unencrypted(
    hostname: str, store_path: str, out_path: Optional[str] = None, password: Optional[str] = None
) -> Result[Dict[str, Any], str]:
    """Export an unencrypted private key for a host.

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
    # Check if host key exists
    if not host_exists(store_path, hostname):
        return Failure(f"Host {hostname} not found in store")

    # Get password using our helper function
    password_result = _get_password_from_ca_config(store_path, password)
    if not password_result:
        return Failure(password_result.error)
    password = password_result.unwrap()

    # Use the exported function from export_deploy module
    return export_host_key_unencrypted_from_store(hostname, store_path, out_path, password)


def deploy_host(hostname: str, store_path: str) -> Result[Dict[str, Any], str]:
    """Run the deployment script for a host.

    Args:
    ----
        hostname: Hostname to deploy
        store_path: Path to the certificate store

    Returns:
    -------
        Result with deployment info dict or error message
    """
    # Load configurations using our helper function
    configs_result = _load_configs(store_path)
    if not configs_result:
        return Failure(configs_result.error)

    _, hosts_config = configs_result.unwrap()

    # Use the function from export_deploy module
    return export_deploy_host(hostname, store_path, hosts_config)


def deploy_all_hosts(store_path: str) -> Result[Dict[str, Any], str]:
    """Deploy all host certificates.

    Args:
    ----
        store_path: Path to the certificate store

    Returns:
    -------
        Result with deployment info dict or error message
    """
    # Load configurations using our helper function
    configs_result = _load_configs(store_path)
    if not configs_result:
        return Failure(configs_result.error)

    _, hosts_config = configs_result.unwrap()

    # Use the function from export_deploy module
    return export_deploy_all_hosts(store_path, hosts_config)


def list_certificates(
    store_path: str, expired: bool = False, expiring_days: Optional[int] = None
) -> Result[Dict[str, Any], str]:
    """List certificates with their expiration dates.

    Args:
    ----
        store_path: Path to the certificate store
        expired: Only include expired certificates if True
        expiring_days: Only include certificates expiring within this many days

    Returns:
    -------
        Result with certificate info dict or error message
    """
    # Get inventory information
    inventory_result = read_inventory(Path(store_path))
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()

    # Get CA information
    ca_info = {
        "serial": inventory.ca.serial,
        "not_before": inventory.ca.not_before.isoformat(),
        "not_after": inventory.ca.not_after.isoformat(),
        "fingerprint": inventory.ca.fingerprint_sha256,
    }

    # Calculate days until CA expiration
    now = datetime.datetime.now(datetime.UTC)
    ca_days_remaining = (inventory.ca.not_after.replace(tzinfo=datetime.UTC) - now).days
    ca_info["days_remaining"] = ca_days_remaining

    # Filter hosts based on expiration criteria
    filtered_hosts = []

    for host in inventory.hosts:
        days_remaining = (host.not_after.replace(tzinfo=datetime.UTC) - now).days

        # Apply filters
        if expired and days_remaining >= 0:
            continue

        if expiring_days is not None and days_remaining > expiring_days:
            continue

        host_info = {
            "name": host.short_name,
            "serial": host.serial,
            "not_before": host.not_before.isoformat(),
            "not_after": host.not_after.isoformat(),
            "fingerprint": host.fingerprint_sha256,
            "renewal_count": host.renewal_count,
            "rekey_count": host.rekey_count,
            "days_remaining": days_remaining,
        }

        filtered_hosts.append(host_info)

    return Success(
        {
            "ca": ca_info,
            "hosts": filtered_hosts,
            "total": len(filtered_hosts),
            "filters": {"expired": expired, "expiring_days": expiring_days},
        }
    )


def clean_certificates(store_path: str, configured_hosts: Optional[List[str]] = None) -> Result[Dict[str, Any], str]:
    """Remove host folders that are no longer in the configuration.

    Args:
    ----
        store_path: Path to the certificate store
        configured_hosts: Optional list of host names from configuration

    Returns:
    -------
        Result with cleanup info dict or error message
    """
    # If no configured_hosts provided, load from configuration
    if configured_hosts is None:
        # Load configurations using our helper function
        configs_result = _load_configs(store_path)
        if not configs_result:
            return Failure(configs_result.error)

        _, hosts_config = configs_result.unwrap()
        configured_hosts = [host.get("name") for host in hosts_config.get("hosts", [])]

    # Get all existing host directories
    existing_hosts_result = store_list_hosts(store_path)
    if not existing_hosts_result:
        return Failure(f"Failed to list hosts: {existing_hosts_result.error}")

    existing_hosts = existing_hosts_result.unwrap()

    # Find hosts to remove
    hosts_to_remove = [host for host in existing_hosts if host not in configured_hosts]

    if not hosts_to_remove:
        return Success({"action": "clean", "removed": [], "message": "No unconfigured hosts found"})

    # Remove each host
    removed_hosts = []
    for hostname in hosts_to_remove:
        delete_result = delete_host(store_path, hostname)
        if delete_result:
            removed_hosts.append(hostname)

    # Update inventory after cleaning
    inventory_result = read_inventory(Path(store_path))
    if inventory_result:
        inventory = inventory_result.unwrap()
        # Hosts should already be removed from files, just need to update inventory

    return Success({"action": "clean", "removed": removed_hosts, "total_removed": len(removed_hosts)})


def get_host_info(hostname: str, store_path: str) -> Result[Dict[str, Any], str]:
    """Get detailed information about a host certificate.

    Args:
    ----
        hostname: Hostname to get info for
        store_path: Path to the certificate store

    Returns:
    -------
        Result with host info dict or error message
    """
    # Check if host exists
    if not host_exists(store_path, hostname):
        return Failure(f"Host {hostname} not found in store")

    # Get host certificate
    cert_result = read_host_cert(store_path, hostname)
    if not cert_result:
        return Failure(f"Failed to load host certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if not cert_deserialize_result:
        return Failure(f"Failed to deserialize certificate: {cert_deserialize_result.error}")

    cert = cert_deserialize_result.unwrap()

    # Get host info from inventory
    host_info_result = inventory_get_host_info(Path(store_path), hostname, cert)
    if not host_info_result:
        return Failure(f"Failed to get host info from inventory: {host_info_result.error}")

    host_info = host_info_result.unwrap()

    return Success(host_info)


def process_csr(
    csr_path: str,
    store_path: str,
    password: Optional[str] = None,
    validity_days: int = 365,
    out_path: Optional[str] = None,
) -> Result[Dict[str, Any], str]:
    """Process a Certificate Signing Request.

    Args:
    ----
        csr_path: Path to the CSR file
        store_path: Path to the certificate store
        password: Optional password for key decryption
        validity_days: Number of days the certificate should be valid
        out_path: Optional path to save the signed certificate to

    Returns:
    -------
        Result with CSR processing info dict or error message
    """
    # Load CSR
    try:
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data)
    except Exception as e:
        return Failure(f"Failed to load CSR: {str(e)}")

    # Verify CSR signature
    if not csr.is_signature_valid:
        return Failure("CSR has an invalid signature")

    # Extract hostname
    hostname = None
    for attr in csr.subject:
        if attr.oid == NameOID.COMMON_NAME:
            # Handle both string and bytes value types
            hostname = attr.value.decode("utf-8") if isinstance(attr.value, bytes) else attr.value
            break

    if not hostname:
        return Failure("Could not extract hostname from CSR")

    # Get password using our helper function
    password_result = _get_password_from_ca_config(store_path, password)
    if not password_result:
        return Failure(password_result.error)
    password = password_result.unwrap()

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store_path, password)
    if not ca_result:
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Load CA config to get hash algorithm
    configs_result = _load_configs(store_path)
    hash_algorithm = "SHA256"  # Default

    if configs_result:
        ca_config, _ = configs_result.unwrap()
        hash_algorithm = ca_config.hash_algorithm

    # Extract SANs from CSR
    alt_names = AlternativeNames()
    for ext in csr.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for san in ext.value:
                if isinstance(san, x509.DNSName):
                    alt_names.dns.append(san.value)
                elif isinstance(san, x509.IPAddress):
                    alt_names.ip.append(str(san.value))
                elif isinstance(san, x509.RFC822Name):
                    alt_names.email.append(san.value)
                elif isinstance(san, UniformResourceIdentifier):
                    alt_names.uri.append(san.value)
                elif isinstance(san, DirectoryName):
                    # Format directory name
                    dn_parts = []
                    for attr in san.value:
                        oid = attr.oid
                        value = attr.value.decode() if isinstance(attr.value, bytes) else attr.value

                        if oid == NameOID.COMMON_NAME:
                            dn_parts.append(f"CN={value}")
                        elif oid == NameOID.ORGANIZATION_NAME:
                            dn_parts.append(f"O={value}")
                        elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                            dn_parts.append(f"OU={value}")
                        elif oid == NameOID.COUNTRY_NAME:
                            dn_parts.append(f"C={value}")
                        elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                            dn_parts.append(f"ST={value}")
                        elif oid == NameOID.LOCALITY_NAME:
                            dn_parts.append(f"L={value}")
                        elif oid == NameOID.EMAIL_ADDRESS:
                            dn_parts.append(f"E={value}")

                    alt_names.directory_name.append(",".join(dn_parts) if dn_parts else "")

    # Create certificate parameters
    cert_params = CertificateParams(
        hostname=hostname,
        ca_key=ca_key,
        ca_cert=ca_cert,
        public_key=csr.public_key(),
        subject=csr.subject,
        validity_days=validity_days,
        alt_names=alt_names if not alt_names.is_empty() else None,
        hash_algorithm=hash_algorithm,
    )

    # Create certificate
    cert_result = create_certificate(cert_params)
    if not cert_result:
        return Failure(f"Failed to create certificate from CSR: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save to file if out_path provided
    if out_path:
        out_file_path = Path(out_path)
        with open(out_file_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

    # Result info
    result_info = {
        "action": "signed_csr",
        "hostname": hostname,
        "validity_days": validity_days,
        "subject": {},
        "sans": {},
    }

    # Add subject information
    for attr in csr.subject:
        attr_name = attr.oid._name
        attr_value = attr.value
        result_info["subject"][attr_name] = attr_value

    # Add SANs
    for name_type in ["dns", "ip", "email", "uri", "directory_name"]:
        values = getattr(alt_names, name_type, [])
        if values:
            result_info["sans"][name_type] = values

    if out_path:
        result_info["cert_path"] = str(out_file_path)

    return Success(result_info)
