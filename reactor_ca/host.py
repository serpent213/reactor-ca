"""Host certificate operations for ReactorCA.

This module provides high-level functions for managing host certificates
in the ReactorCA tool. It relies on the core modules for implementation details.
"""

import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reactor_ca import models

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.general_name import DirectoryName, UniformResourceIdentifier
from cryptography.x509.oid import NameOID

from reactor_ca.ca import load_ca_key_cert
from reactor_ca.config import load_config
from reactor_ca.export_deploy import (
    deploy_all_hosts as export_deploy_all_hosts,
)
from reactor_ca.export_deploy import (
    deploy_host as export_deploy_host,
)
from reactor_ca.export_deploy import (
    export_host_cert,
    export_host_chain,
    export_host_key_unencrypted_from_store,
    run_deploy_command,
)
from reactor_ca.inventory import (
    get_host_info as inventory_get_host_info,
)
from reactor_ca.inventory import (
    read_inventory,
    update_inventory_with_host_cert,
)
from reactor_ca.models import (
    CA,
    AlternativeNames,
    CAConfig,
    CertificateParams,
    HostConfig,
    SubjectIdentity,
    ValidityConfig,
)
from reactor_ca.password import get_password
from reactor_ca.paths import resolve_paths
from reactor_ca.result import Failure, Result, Success
from reactor_ca.store import (
    delete_host,
    host_exists,
    read_host_cert,
    read_host_key,
    write_host_cert,
    write_host_key,
)
from reactor_ca.store import (
    list_hosts as store_list_hosts,
)
from reactor_ca.x509_crypto import (
    create_certificate,
    deserialize_certificate,
    deserialize_private_key,
    generate_key,
    verify_key_algorithm,
)


def _load_configs(config: "models.Config") -> Result[tuple[CAConfig, dict[str, Any]], str]:
    """Get CA and hosts configurations from the Config object.

    Args:
    ----
        config: Config object with loaded configurations

    Returns:
    -------
        Result with tuple of (CAConfig, hosts_config) or error message

    """
    # Configurations are already loaded in the Config object
    return Success((config.ca_config, config.hosts_config))


def _get_password_from_store(store: "models.Store", config: "models.Config") -> Result[str, str]:
    """Get password from Store or prompt using config parameters.

    Args:
    ----
        store: Store object that might already be unlocked
        config: Config object with password configuration

    Returns:
    -------
        Result with password string or error message

    """
    # If store is already unlocked with a password, use it
    if store.unlocked and store.password:
        return Success(store.password)

    # Store is not unlocked, prompt for password using config settings
    password_result = get_password(
        min_length=config.ca_config.password.min_length,
        password_file=config.ca_config.password.file,
        env_var=config.ca_config.password.env_var,
        prompt_message="Enter CA master password: ",
        confirm=False,
    )

    if isinstance(password_result, Failure):
        return Failure(f"Failed to get password: {password_result.error}")

    password = password_result.unwrap()
    if password is None:
        return Failure("Password cannot be None")

    return Success(password)


def issue_certificate(
    hostname: str, config: "models.Config", store: "models.Store", no_export: bool = False, do_deploy: bool = False
) -> Result[dict[str, Any], str]:
    """Issue or renew a certificate for a host.

    Args:
    ----
        hostname: Hostname for the certificate
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get configurations from the Config object
    hosts_config = config.hosts_config

    # Use password from store
    password = store.password

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store)
    if isinstance(ca_result, Failure):
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Find host config
    host_config = None
    # Extract the hosts list from the config, handling different possible types
    host_list: list[dict[str, Any]] = []
    if isinstance(hosts_config, dict) and "hosts" in hosts_config:
        hosts_config_list = hosts_config["hosts"]
        if isinstance(hosts_config_list, list):
            host_list = hosts_config_list
    if host_list and isinstance(host_list, list):
        for host in host_list:
            if host.get("name") == hostname:
                host_config = host
                break

    if not host_config:
        return Failure(f"Host {hostname} not found in hosts configuration")

    # Check if certificate and key exist
    key_algorithm = host_config.get("key_algorithm", "RSA2048")
    is_new = not host_exists(store.path, hostname)

    # Handle key creation or loading
    private_key: PrivateKeyTypes | None = None

    if is_new:
        # Create new key
        key_result = generate_key(key_algorithm)
        if isinstance(key_result, Failure):
            return Failure(f"Failed to generate key: {key_result.error}")
        private_key = key_result.unwrap()
    else:
        # Use a temporary variable with explicit typing

        # Load existing key
        key_result = read_host_key(store.path, hostname, password)  # type: ignore
        if isinstance(key_result, Failure):
            return Failure(f"Failed to load host key: {key_result.error}")

        # Process the key data
        key_bytes_result = key_result.unwrap()
        password_bytes = password.encode() if password else None

        # Use a try-except block to handle the key deserialization
        try:
            # Make sure key_bytes_result is actually bytes
            if isinstance(key_bytes_result, bytes):
                private_key = load_pem_private_key(key_bytes_result, password_bytes)
            else:
                return Failure(f"Expected bytes, got {type(key_bytes_result).__name__}")
        except Exception as e:
            return Failure(f"Failed to deserialize private key: {str(e)}")

        # Verify key algorithm
        key_algorithm_result = verify_key_algorithm(private_key, key_algorithm)
        if isinstance(key_algorithm_result, Failure):
            return Failure("Key algorithm mismatch. To use a new algorithm, please use rekey_host instead.")

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

    # Create subject identity from host config
    subject_identity = SubjectIdentity(
        common_name=common_name,
        organization=host_config_obj.organization or "",
        organization_unit=host_config_obj.organization_unit or "",
        country=host_config_obj.country or "",
        state=host_config_obj.state or "",
        locality=host_config_obj.locality or "",
        email=host_config_obj.email or "",
    )

    # Create CA object
    ca_obj = CA(key=ca_key, cert=ca_cert, ca_config=config.ca_config, config=config)

    cert_params = CertificateParams(
        subject_identity=subject_identity,
        ca=ca_obj,
        private_key=private_key,
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=hash_algorithm,
    )

    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_host_cert(store.path, hostname, cert_bytes)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    if is_new and private_key is not None:
        # Serialize the private key to bytes
        key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        key_save_result = write_host_key(store.path, hostname, key_bytes, password)
        if isinstance(key_save_result, Failure):
            return Failure(f"Failed to save host key: {key_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store.path))
    if isinstance(inventory_result, Failure):
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()
    update_result = update_inventory_with_host_cert(
        Path(store.path), hostname, cert, inventory, rekeyed=False, renewal_count_increment=0 if is_new else 1
    )
    if isinstance(update_result, Failure):
        return Failure(f"Failed to update inventory: {update_result.error}")

    # Export certificate if requested
    export_info = {}
    if not no_export and "export" in host_config:
        export_config = host_config["export"]

        if "cert" in export_config:
            cert_path = Path(export_config["cert"])
            cert_export_result = export_host_cert(cert, cert_path)
            if isinstance(cert_export_result, Success):
                export_info["cert"] = str(cert_path)

        if "chain" in export_config:
            chain_path = Path(export_config["chain"])
            chain_export_result = export_host_chain(cert, ca_cert, chain_path)
            if isinstance(chain_export_result, Success):
                export_info["chain"] = str(chain_path)

    # Deploy if requested
    deploy_info = {}
    if do_deploy and "deploy" in host_config:
        deploy_command = host_config["deploy"].get("command")
        if deploy_command:
            deploy_result = run_deploy_command(deploy_command, hostname)
            if isinstance(deploy_result, Success):
                deploy_info["command"] = deploy_command
                deploy_info["output"] = deploy_result.unwrap()

    # Prepare result info
    result_info = {
        "action": "created" if is_new else "renewed",
        "hostname": hostname,
        "common_name": common_name,
        "cert_path": str(store.get_host_cert_path(hostname)),
        "key_path": str(store.get_host_key_path(hostname)),
        "validity_days": validity_days,
        "is_new": is_new,
    }

    if export_info:
        result_info["export"] = export_info
    if deploy_info:
        result_info["deploy"] = deploy_info

    return Success(result_info)


def issue_all_certificates(
    config: "models.Config", store: "models.Store", no_export: bool = False, do_deploy: bool = False
) -> Result[dict[str, Any], str]:
    """Issue or renew certificates for all hosts in configuration.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get hosts from configuration
    hosts_config = config.hosts_config
    hosts = list(hosts_config.keys())

    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0
    results = {}

    for hostname in hosts:
        cert_result = issue_certificate(hostname, config, store, no_export, do_deploy)

        if isinstance(cert_result, Success):
            success_count += 1
            results[hostname] = cert_result.unwrap()
        else:
            error_count += 1
            if isinstance(cert_result, Failure):
                results[hostname] = {"error": cert_result.error}
            else:
                results[hostname] = {"error": "Unknown error"}

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
    hostname: str, config: "models.Config", store: "models.Store", no_export: bool = False, do_deploy: bool = False
) -> Result[dict[str, Any], str]:
    """Generate a new key and certificate for a host.

    Args:
    ----
        hostname: Hostname for the certificate
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get configurations from the Config object
    hosts_config = config.hosts_config

    # Use password from store
    password = store.password

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store)
    if isinstance(ca_result, Failure):
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Find host config
    host_config = None
    # Extract the hosts list from the config, handling different possible types
    host_list: list[dict[str, Any]] = []
    if isinstance(hosts_config, dict) and "hosts" in hosts_config:
        hosts_config_list = hosts_config["hosts"]
        if isinstance(hosts_config_list, list):
            host_list = hosts_config_list
    if host_list and isinstance(host_list, list):
        for host in host_list:
            if host.get("name") == hostname:
                host_config = host
                break

    if not host_config:
        return Failure(f"Host {hostname} not found in hosts configuration")

    # Get key algorithm from config
    key_algorithm = host_config.get("key_algorithm", "RSA2048")

    # Create new key
    key_result = generate_key(key_algorithm)
    if isinstance(key_result, Failure):
        return Failure(f"Failed to generate key: {key_result.error}")
    private_key: PrivateKeyTypes = key_result.unwrap()

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

    # Create subject identity from host config
    subject_identity = SubjectIdentity(
        common_name=common_name,
        organization=host_config_obj.organization or "",
        organization_unit=host_config_obj.organization_unit or "",
        country=host_config_obj.country or "",
        state=host_config_obj.state or "",
        locality=host_config_obj.locality or "",
        email=host_config_obj.email or "",
    )

    # Create CA object
    ca_obj = CA(key=ca_key, cert=ca_cert, ca_config=config.ca_config, config=config)

    cert_params = CertificateParams(
        subject_identity=subject_identity,
        ca=ca_obj,
        private_key=private_key,
        validity_days=validity_days,
        alt_names=alt_names,
        hash_algorithm=hash_algorithm,
    )

    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save certificate and key
    cert_bytes = cert.public_bytes(Encoding.PEM)
    cert_save_result = write_host_cert(store.path, hostname, cert_bytes)
    if isinstance(cert_save_result, Failure):
        return Failure(f"Failed to save host certificate: {cert_save_result.error}")

    if private_key is None:
        return Failure("Private key is None, cannot export")

    key_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_host_key(store.path, hostname, key_bytes, password)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save host key: {key_save_result.error}")

    # Update inventory
    inventory_result = read_inventory(Path(store.path))
    if isinstance(inventory_result, Failure):
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()
    update_result = update_inventory_with_host_cert(
        Path(store.path), hostname, cert, inventory, rekeyed=True, renewal_count_increment=1
    )
    if isinstance(update_result, Failure):
        return Failure(f"Failed to update inventory: {update_result.error}")

    # Export certificate if requested
    export_info = {}
    if not no_export and "export" in host_config:
        export_config = host_config["export"]

        if "cert" in export_config:
            cert_path = Path(export_config["cert"])
            cert_export_result = export_host_cert(cert, cert_path)
            if isinstance(cert_export_result, Success):
                export_info["cert"] = str(cert_path)

        if "chain" in export_config:
            chain_path = Path(export_config["chain"])
            chain_export_result = export_host_chain(cert, ca_cert, chain_path)
            if isinstance(chain_export_result, Success):
                export_info["chain"] = str(chain_path)

    # Deploy if requested
    deploy_info = {}
    if do_deploy and "deploy" in host_config:
        deploy_command = host_config["deploy"].get("command")
        if deploy_command:
            deploy_result = run_deploy_command(deploy_command, hostname)
            if isinstance(deploy_result, Success):
                deploy_info["command"] = deploy_command
                deploy_info["output"] = deploy_result.unwrap()

    # Prepare result info
    result_info = {
        "action": "rekeyed",
        "hostname": hostname,
        "common_name": common_name,
        "cert_path": str(store.get_host_cert_path(hostname)),
        "key_path": str(store.get_host_key_path(hostname)),
        "validity_days": validity_days,
    }

    if export_info:
        result_info["export"] = export_info
    if deploy_info:
        result_info["deploy"] = deploy_info

    return Success(result_info)


def rekey_all_hosts(
    config: "models.Config", store: "models.Store", no_export: bool = False, do_deploy: bool = False
) -> Result[dict[str, Any], str]:
    """Rekey all hosts in configuration.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        no_export: Skip exporting files if True
        do_deploy: Deploy certificates after creation if True

    Returns:
    -------
        Result with certificate info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Get hosts from configuration
    hosts_config = config.hosts_config
    hosts = list(hosts_config.keys())

    if not hosts:
        return Failure("No hosts found in configuration")

    success_count = 0
    error_count = 0
    results = {}

    for hostname in hosts:
        rekey_result = rekey_host(hostname, config, store, no_export, do_deploy)

        if isinstance(rekey_result, Success):
            success_count += 1
            results[hostname] = rekey_result.unwrap()
        else:
            error_count += 1
            if isinstance(rekey_result, Failure):
                results[hostname] = {"error": rekey_result.error}
            else:
                results[hostname] = {"error": "Unknown error"}

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
    hostname: str, key_path: str, config: "models.Config", store: "models.Store", src_password: str | None = None
) -> Result[dict[str, Any], str]:
    """Import an existing private key for a host.

    Args:
    ----
        hostname: Hostname for the key
        key_path: Path to the key file to import
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        src_password: Optional password for decrypting the source key

    Returns:
    -------
        Result with key info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Check if source key file exists
    src_key_path = Path(key_path)
    if not src_key_path.exists():
        return Failure(f"Key file not found: {key_path}")

    # Check if host already has a key
    if host_exists(store.path, hostname):
        return Failure(
            f"Certificate or key for {hostname} already exists. Remove it first or use a different hostname."
        )

    # Use password from store
    store_password = store.password

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
                if isinstance(src_password_result, Failure):
                    return Failure(f"Failed to get source key password: {src_password_result.error}")
                src_password = src_password_result.unwrap()

                # Make sure password is not None before encoding
                if src_password is None:
                    return Failure("Source password cannot be None")

                private_key_result = deserialize_private_key(key_data, src_password.encode())
                if isinstance(private_key_result, Failure):
                    return Failure(f"Failed to deserialize private key: {private_key_result.error}")
        except Exception as e:
            return Failure(f"Error loading key: {str(e)}")

        private_key = private_key_result.unwrap()
    except Exception as e:
        return Failure(f"Error loading key file: {str(e)}")

    # Save the key to the store
    if private_key is None:
        return Failure("Private key is None, cannot export")

    key_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_save_result = write_host_key(store.path, hostname, key_bytes, store_password)
    if isinstance(key_save_result, Failure):
        return Failure(f"Failed to save host key: {key_save_result.error}")

    return Success(
        {
            "action": "imported_key",
            "hostname": hostname,
            "key_path": str(store.get_host_key_path(hostname)),
            "source_path": str(src_key_path),
        }
    )


def export_host_key_unencrypted_wrapper(
    hostname: str, store: "models.Store", out_path: str | None = None
) -> Result[dict[str, Any], str]:
    """Export an unencrypted private key for a host.

    Args:
    ----
        hostname: Hostname for the key
        store: Store object (already unlocked with password)
        out_path: Path to save the unencrypted key (if None, return key data in result)

    Returns:
    -------
        Result with key info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

    # Check if host key exists
    if not host_exists(store.path, hostname):
        return Failure(f"Host {hostname} not found in store")

    # Use the exported function from export_deploy module
    password = store.password if store.password else ""
    return export_host_key_unencrypted_from_store(hostname, store.path, password, out_path)


def deploy_host(hostname: str, config: "models.Config", store: "models.Store") -> Result[dict[str, Any], str]:
    """Run the deployment script for a host.

    Args:
    ----
        hostname: Hostname to deploy
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with deployment info dict or error message

    """
    # Get configurations directly from Config object
    hosts_config = config.hosts_config

    # Use the function from export_deploy module
    return export_deploy_host(hostname, store.path, hosts_config)


def deploy_all_hosts(config: "models.Config", store: "models.Store") -> Result[dict[str, Any], str]:
    """Deploy all host certificates.

    Args:
    ----
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)

    Returns:
    -------
        Result with deployment info dict or error message

    """
    # Get configurations directly from Config object
    hosts_config = config.hosts_config

    # Use the function from export_deploy module
    return export_deploy_all_hosts(store.path, hosts_config)


def list_certificates(
    store: "models.Store", expired: bool = False, expiring_days: int | None = None
) -> Result[dict[str, Any], str]:
    """List certificates with their expiration dates.

    Args:
    ----
        store: Store object containing path information
        expired: Only include expired certificates if True
        expiring_days: Only include certificates expiring within this many days

    Returns:
    -------
        Result with certificate info dict or error message

    """
    # Get inventory information
    inventory_result = read_inventory(Path(store.path))
    if isinstance(inventory_result, Failure):
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
    ca_info["days_remaining"] = str(ca_days_remaining)

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


def clean_certificates(store_path: str, configured_hosts: list[str] | None = None) -> Result[dict[str, Any], str]:
    """Remove host folders that are no longer in the configuration.

    Args:
    ----
        store_path: Path to the certificate store
        configured_hosts: Optional list of host names from configuration

    Returns:
    -------
        Result with cleanup info dict or error message

    """
    # If no configured_hosts provided, try to load from configuration
    if configured_hosts is None:
        # We need a Config object, but we only have a path
        # Let's handle this differently - we'll just load the hosts directly

        # Get config and store paths
        config_path, _ = resolve_paths(store_dir=store_path)

        # Load config
        config_result = load_config(str(config_path))
        if isinstance(config_result, Failure):
            return Failure(f"Failed to load configuration: {config_result.error}")

        config = config_result.unwrap()
        hosts_config = config.hosts_config

        # Extract host names from config
        configured_hosts = []
        if isinstance(hosts_config, dict) and "hosts" in hosts_config:
            host_list = hosts_config["hosts"]
            if isinstance(host_list, list):
                for host in host_list:
                    name = host.get("name")
                    if name and isinstance(name, str):
                        configured_hosts.append(name)

    # Get all existing host directories
    existing_hosts_result = store_list_hosts(store_path)
    if isinstance(existing_hosts_result, Failure):
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
        if isinstance(delete_result, Success):
            removed_hosts.append(hostname)

    # Update inventory after cleaning
    inventory_result = read_inventory(Path(store_path))
    if isinstance(inventory_result, Success):
        inventory_result.unwrap()
        # Hosts should already be removed from files, just need to update inventory

    return Success({"action": "clean", "removed": removed_hosts, "total_removed": len(removed_hosts)})


def get_host_info(hostname: str, store_path: str) -> Result[dict[str, Any], str]:
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
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to load host certificate: {cert_result.error}")

    cert_data = cert_result.unwrap()
    cert_deserialize_result = deserialize_certificate(cert_data)
    if isinstance(cert_deserialize_result, Failure):
        return Failure(f"Failed to deserialize certificate: {cert_deserialize_result.error}")

    cert = cert_deserialize_result.unwrap()

    # Get host info from inventory
    host_info_result = inventory_get_host_info(Path(store_path), hostname, cert)
    if isinstance(host_info_result, Failure):
        return Failure(f"Failed to get host info from inventory: {host_info_result.error}")

    host_info = host_info_result.unwrap()

    return Success(host_info)


def process_csr(
    csr_path: str,
    config: "models.Config",
    store: "models.Store",
    validity_days: int = 365,
    out_path: str | None = None,
) -> Result[dict[str, Any], str]:
    """Process a Certificate Signing Request.

    Args:
    ----
        csr_path: Path to the CSR file
        config: Config object with loaded configurations
        store: Store object (already unlocked with password)
        validity_days: Number of days the certificate should be valid
        out_path: Optional path to save the signed certificate to

    Returns:
    -------
        Result with CSR processing info dict or error message

    """
    # Make sure store is unlocked
    if not store.unlocked or not store.password:
        return Failure("Store must be unlocked and have a password set")

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

    # Use password from store

    # Load CA key and certificate
    ca_result = load_ca_key_cert(store)
    if isinstance(ca_result, Failure):
        return Failure(f"Failed to load CA: {ca_result.error}")
    ca_key, ca_cert = ca_result.unwrap()

    # Get hash algorithm from config
    hash_algorithm = config.ca_config.hash_algorithm

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

    # Extract subject identity from CSR subject
    subject_identity = SubjectIdentity(
        common_name=hostname,
        # Try to extract other attributes from the CSR subject
        organization="",
        organization_unit="",
        country="",
        state="",
        locality="",
        email="",
    )

    # Extract subject components from the CSR
    for attr in csr.subject:
        attr_value = str(attr.value)
        if attr.oid == NameOID.ORGANIZATION_NAME:
            subject_identity.organization = attr_value
        elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            subject_identity.organization_unit = attr_value
        elif attr.oid == NameOID.COUNTRY_NAME:
            subject_identity.country = attr_value
        elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
            subject_identity.state = attr_value
        elif attr.oid == NameOID.LOCALITY_NAME:
            subject_identity.locality = attr_value
        elif attr.oid == NameOID.EMAIL_ADDRESS:
            subject_identity.email = attr_value

    # Create CA object
    ca_obj = CA(key=ca_key, cert=ca_cert, ca_config=config.ca_config, config=config)

    # Create certificate parameters
    cert_params = CertificateParams(
        subject_identity=subject_identity,
        ca=ca_obj,
        private_key=None,  # We'll use the public key from the CSR
        validity_days=validity_days,
        alt_names=alt_names if not alt_names.is_empty() else None,
        hash_algorithm=hash_algorithm,
    )

    # Create certificate
    cert_result = create_certificate(cert_params)
    if isinstance(cert_result, Failure):
        return Failure(f"Failed to create certificate from CSR: {cert_result.error}")
    cert = cert_result.unwrap()

    # Save to file if out_path provided
    if out_path and cert is not None:
        out_file_path = Path(out_path)
        with open(out_file_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

    # Result info
    subject_dict = {}
    sans_dict = {}

    # Add subject information
    for attr in csr.subject:
        attr_name = attr.oid._name
        # Ensure we have a string value
        if isinstance(attr.value, bytes):
            attr_value = attr.value.decode("utf-8")
        else:
            attr_value = str(attr.value)
        subject_dict[attr_name] = attr_value

    # Add SANs
    for name_type in ["dns", "ip", "email", "uri", "directory_name"]:
        values = getattr(alt_names, name_type, [])
        if values:
            sans_dict[name_type] = values

    # Create the full result info
    result_info = {
        "action": "signed_csr",
        "hostname": hostname,
        "validity_days": validity_days,
        "subject": subject_dict,
        "sans": sans_dict,
    }

    if out_path:
        result_info["cert_path"] = str(out_file_path)

    return Success(result_info)
