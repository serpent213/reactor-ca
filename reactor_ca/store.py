"""Certificate Store and Inventory Management.

This module provides functions for managing certificate storage,
inventory tracking, and file operations for the ReactorCA tool.
"""

import datetime
import logging
import os
from pathlib import Path
from typing import Any, cast

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from rich.console import Console

from reactor_ca.config import Config, load_ca_config
from reactor_ca.models import (
    CAConfig,
    CAInventoryEntry,
    Inventory,
    InventoryEntry,
    Store,
)
from reactor_ca.password import get_password, read_password_from_file, verify_password
from reactor_ca.paths import (
    ensure_dirs,
    get_ca_cert_path,
    get_ca_config_path,
    get_ca_key_path,
    get_host_cert_path,
    get_host_dir,
    get_host_key_path,
    get_hosts_config_path,
    get_hosts_dir,
    get_inventory_path,
    resolve_paths,
)
from reactor_ca.result import Result, Success, Failure

# Module-level console instance
CONSOLE = Console()

# Setup logging
logger = logging.getLogger(__name__)


def create_store(config_dir: str | None = None, store_dir: str | None = None) -> Store:
    """
    Create a new Store instance with the specified or default paths.
    
    Args:
        config_dir: Optional path to configuration directory
        store_dir: Optional path to store directory
        
    Returns:
        Initialized Store instance
    """
    config_path, store_path = resolve_paths(config_dir, store_dir)
    return Store(path=str(store_path))


def initialize_store(store: Store) -> Result[Store, str]:
    """
    Initialize the store directory structure and create empty inventory if needed.
    
    Args:
        store: Store instance
        
    Returns:
        Result with updated Store or error message
    """
    try:
        config_path, store_path = resolve_paths(None, store.path)
        ensure_dirs(config_path, store_path)
        
        # Initialize inventory if it doesn't exist
        inventory_path = get_inventory_path(store_path)
        if not inventory_path.exists():
            inventory = {
                "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
                "ca": {},
                "hosts": [],
            }
            
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            with open(inventory_path, "w", encoding="locale") as f:
                yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
                
        logger.info(f"Initialized certificate store at {store_path}")
        return Success(store)
    except Exception as e:
        return Failure(f"Failed to initialize store: {str(e)}")


def unlock_store(store: Store, password: str | None = None, ca_init: bool = False) -> Result[Store, str]:
    """
    Unlock the store with the provided password.
    
    If password is not provided, tries multiple sources in order:
    1. If store is already unlocked, returns success
    2. Password file specified in config
    3. Environment variable specified in config
    4. User prompt
    
    Args:
        store: Store instance
        password: Optional explicit password to use
        ca_init: Whether this is for CA initialization (skip validation)
        
    Returns:
        Result with unlocked Store or error message
    """
    # If already unlocked with a password, return success
    if store.unlocked and store.password:
        return Success(store)
    
    # Load CA config to get password settings
    config_path, store_path = resolve_paths(None, store.path)
    ca_config_path = get_ca_config_path(config_path)
    
    try:
        if ca_config_path.exists():
            ca_config = load_ca_config(ca_config_path)
            min_length = ca_config.password.min_length
            password_file = ca_config.password.file
            env_var = ca_config.password.env_var
        else:
            # Default values if config doesn't exist
            min_length = 8
            password_file = ""
            env_var = "REACTOR_CA_PASSWORD"
    except Exception as e:
        return Failure(f"Failed to load CA config: {str(e)}")
    
    # Get password from appropriate source
    password_result = get_password(
        store=store,
        min_length=min_length,
        password_file=password_file if password_file else None,
        env_var=env_var if env_var else None,
        prompt_message="Enter CA master password: ",
        confirm=ca_init,
    )
    
    if not password_result:
        return Failure(f"Failed to get password: {password_result.error}")
    
    password = password_result.unwrap()
    
    # If in CA init mode, just store password without validation
    if ca_init:
        return Success(Store(
            path=store.path,
            password=password,
            unlocked=True
        ))
    
    # Validate against CA key if it exists
    ca_key_path = get_ca_key_path(Path(store.path))
    if ca_key_path.exists():
        try:
            # Try to load it to verify the password
            with open(ca_key_path, "rb") as f:
                key_data = f.read()
                load_pem_private_key(key_data, password.encode("utf-8"))
            
            # Password is valid
            return Success(Store(
                path=store.path,
                password=password,
                unlocked=True
            ))
        except Exception as e:
            return Failure(f"Failed to unlock CA store: {str(e)}")
    else:
        # If key doesn't exist yet, store password for later use
        return Success(Store(
            path=store.path,
            password=password,
            unlocked=True
        ))


def require_unlocked(store: Store) -> Result[Store, str]:
    """
    Check if the store is unlocked and return error if not.
    
    Args:
        store: Store instance
        
    Returns:
        Result with the store if unlocked, or error message
    """
    if store.unlocked and store.password:
        return Success(store)
    return Failure("Certificate store is locked. Call unlock_store() first.")


def read_ca_cert(store: Store) -> Result[x509.Certificate, str]:
    """
    Read the CA certificate from the store.
    
    Args:
        store: Store instance
        
    Returns:
        Result with certificate or error message
    """
    cert_path = get_ca_cert_path(Path(store.path))
    if not cert_path.exists():
        return Failure(f"CA certificate not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
        
        logger.debug(f"Loaded CA certificate from {cert_path}")
        return Success(cert)
    except Exception as e:
        return Failure(f"Failed to load CA certificate: {str(e)}")


def write_ca_cert(store: Store, cert: x509.Certificate) -> Result[Store, str]:
    """
    Write the CA certificate to the store.
    
    Args:
        store: Store instance
        cert: CA certificate to write
        
    Returns:
        Result with updated Store or error message
    """
    cert_path = get_ca_cert_path(Path(store.path))
    
    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write certificate
        cert_bytes = cert.public_bytes(Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        
        logger.info(f"Saved CA certificate to {cert_path}")
        
        # Update inventory
        update_result = update_inventory(store)
        if not update_result:
            return Failure(f"Failed to update inventory: {update_result.error}")
        
        return Success(update_result.unwrap())
    except Exception as e:
        return Failure(f"Failed to write CA certificate: {str(e)}")


def read_ca_key(store: Store) -> Result[PrivateKeyTypes, str]:
    """
    Read the encrypted CA private key from the store.
    
    Args:
        store: Store instance
        
    Returns:
        Result with private key or error message
    """
    # Check if store is unlocked
    unlocked_result = require_unlocked(store)
    if not unlocked_result:
        return Failure(unlocked_result.error)
    
    key_path = get_ca_key_path(Path(store.path))
    if not key_path.exists():
        return Failure(f"CA private key not found at {key_path}")
    
    if not store.password:
        return Failure("No password available to decrypt the key")
    
    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
            key = load_pem_private_key(key_data, store.password.encode("utf-8"))
        
        logger.debug(f"Loaded CA private key from {key_path}")
        return Success(key)
    except Exception as e:
        return Failure(f"Failed to load CA private key: {str(e)}")


def write_ca_key(store: Store, key: PrivateKeyTypes) -> Result[Store, str]:
    """
    Write the encrypted CA private key to the store.
    
    Args:
        store: Store instance
        key: Private key to write
        
    Returns:
        Result with updated Store or error message
    """
    # Check if store is unlocked
    unlocked_result = require_unlocked(store)
    if not unlocked_result:
        return Failure(unlocked_result.error)
    
    key_path = get_ca_key_path(Path(store.path))
    
    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Ensure password exists
        if not store.password:
            return Failure("Cannot save encrypted key: no password available")
        
        # Encrypt with password
        encryption = BestAvailableEncryption(store.password.encode("utf-8"))
        key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
        
        # Write key
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        
        logger.info(f"Saved encrypted CA private key to {key_path}")
        return Success(store)
    except Exception as e:
        return Failure(f"Failed to write CA private key: {str(e)}")


def read_host_cert(store: Store, host_id: str) -> Result[x509.Certificate, str]:
    """
    Read a host certificate from the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        
    Returns:
        Result with certificate or error message
    """
    cert_path = get_host_cert_path(Path(store.path), host_id)
    if not cert_path.exists():
        return Failure(f"Certificate for {host_id} not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
        
        logger.debug(f"Loaded certificate for {host_id} from {cert_path}")
        return Success(cert)
    except Exception as e:
        return Failure(f"Failed to load certificate for {host_id}: {str(e)}")


def write_host_cert(store: Store, host_id: str, cert: x509.Certificate) -> Result[Store, str]:
    """
    Write a host certificate to the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        cert: Certificate to write
        
    Returns:
        Result with updated Store or error message
    """
    cert_path = get_host_cert_path(Path(store.path), host_id)
    
    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write certificate
        cert_bytes = cert.public_bytes(Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        
        logger.info(f"Saved certificate for {host_id} to {cert_path}")
        
        # Update inventory
        update_result = update_inventory(store)
        if not update_result:
            return Failure(f"Failed to update inventory: {update_result.error}")
        
        return Success(update_result.unwrap())
    except Exception as e:
        return Failure(f"Failed to write certificate for {host_id}: {str(e)}")


def read_host_key(store: Store, host_id: str) -> Result[PrivateKeyTypes, str]:
    """
    Read the encrypted host private key from the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        
    Returns:
        Result with private key or error message
    """
    # Check if store is unlocked
    unlocked_result = require_unlocked(store)
    if not unlocked_result:
        return Failure(unlocked_result.error)
    
    key_path = get_host_key_path(Path(store.path), host_id)
    if not key_path.exists():
        return Failure(f"Private key for {host_id} not found at {key_path}")
    
    if not store.password:
        return Failure("No password available to decrypt the key")
    
    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
            key = load_pem_private_key(key_data, store.password.encode("utf-8"))
        
        logger.debug(f"Loaded private key for {host_id} from {key_path}")
        return Success(key)
    except Exception as e:
        return Failure(f"Failed to load private key for {host_id}: {str(e)}")


def write_host_key(store: Store, host_id: str, key: PrivateKeyTypes) -> Result[Store, str]:
    """
    Write the encrypted host private key to the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        key: Private key to write
        
    Returns:
        Result with updated Store or error message
    """
    # Check if store is unlocked
    unlocked_result = require_unlocked(store)
    if not unlocked_result:
        return Failure(unlocked_result.error)
    
    key_path = get_host_key_path(Path(store.path), host_id)
    
    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Ensure password exists
        if not store.password:
            return Failure("Cannot save encrypted key: no password available")
        
        # Encrypt with password
        encryption = BestAvailableEncryption(store.password.encode("utf-8"))
        key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
        
        # Write key
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        
        logger.info(f"Saved encrypted private key for {host_id} to {key_path}")
        return Success(store)
    except Exception as e:
        return Failure(f"Failed to write private key for {host_id}: {str(e)}")


def read_inventory(store: Store) -> Result[Inventory, str]:
    """
    Read the certificate inventory from the store.
    
    Args:
        store: Store instance
        
    Returns:
        Result with Inventory or error message
    """
    inventory_path = get_inventory_path(Path(store.path))
    
    if not inventory_path.exists():
        # Create empty inventory structure
        now = datetime.datetime.now(datetime.UTC)
        empty_ca_entry = CAInventoryEntry(
            serial="",
            not_before=now,
            not_after=now,
            fingerprint_sha256="",
        )
        
        return Success(Inventory(ca=empty_ca_entry, hosts=[]))
    
    try:
        with open(inventory_path, encoding="locale") as f:
            inventory_data = yaml.safe_load(f)
        
        # Convert raw inventory data to structured Inventory
        ca_data = inventory_data.get("ca", {})
        hosts_data = inventory_data.get("hosts", [])
        
        # Create CA inventory entry
        if ca_data:
            ca_entry = CAInventoryEntry(
                serial=ca_data.get("serial", ""),
                not_before=datetime.datetime.fromisoformat(ca_data.get("not_before", datetime.datetime.now(datetime.UTC).isoformat())),
                not_after=datetime.datetime.fromisoformat(ca_data.get("not_after", datetime.datetime.now(datetime.UTC).isoformat())),
                fingerprint_sha256=ca_data.get("fingerprint", ""),
                renewal_count=ca_data.get("renewal_count", 0),
                rekey_count=ca_data.get("rekey_count", 0),
            )
        else:
            # Create empty CA entry if none exists
            now = datetime.datetime.now(datetime.UTC)
            ca_entry = CAInventoryEntry(
                serial="",
                not_before=now,
                not_after=now,
                fingerprint_sha256="",
            )
        
        # Create host inventory entries
        host_entries = []
        for host_data in hosts_data:
            host_entry = InventoryEntry(
                short_name=host_data.get("name", ""),
                serial=host_data.get("serial", ""),
                not_before=datetime.datetime.fromisoformat(host_data.get("not_before", datetime.datetime.now(datetime.UTC).isoformat())),
                not_after=datetime.datetime.fromisoformat(host_data.get("not_after", datetime.datetime.now(datetime.UTC).isoformat())),
                fingerprint_sha256=host_data.get("fingerprint", ""),
                renewal_count=host_data.get("renewal_count", 0),
                rekey_count=host_data.get("rekey_count", 0),
            )
            host_entries.append(host_entry)
        
        inventory = Inventory(ca=ca_entry, hosts=host_entries)
        return Success(inventory)
    except Exception as e:
        return Failure(f"Failed to load inventory: {str(e)}")


def write_inventory(store: Store, inventory: Inventory) -> Result[Store, str]:
    """
    Write the certificate inventory to the store.
    
    Args:
        store: Store instance
        inventory: Inventory to write
        
    Returns:
        Result with updated Store or error message
    """
    inventory_path = get_inventory_path(Path(store.path))
    
    try:
        # Ensure parent directory exists
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert inventory to dictionary format
        inventory_dict = {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {
                "serial": inventory.ca.serial,
                "not_before": inventory.ca.not_before.isoformat(),
                "not_after": inventory.ca.not_after.isoformat(),
                "fingerprint": inventory.ca.fingerprint_sha256,
                "renewal_count": inventory.ca.renewal_count,
                "rekey_count": inventory.ca.rekey_count,
            },
            "hosts": [
                {
                    "name": host.short_name,
                    "serial": host.serial,
                    "not_before": host.not_before.isoformat(),
                    "not_after": host.not_after.isoformat(),
                    "fingerprint": host.fingerprint_sha256,
                    "renewal_count": host.renewal_count,
                    "rekey_count": host.rekey_count,
                }
                for host in inventory.hosts
            ],
        }
        
        # Write inventory
        with open(inventory_path, "w", encoding="locale") as f:
            yaml.dump(inventory_dict, f, default_flow_style=False, sort_keys=False)
        
        logger.debug(f"Saved inventory to {inventory_path}")
        return Success(store)
    except Exception as e:
        return Failure(f"Failed to write inventory: {str(e)}")


def update_inventory(store: Store) -> Result[Store, str]:
    """
    Update inventory based on certificate files.
    
    Args:
        store: Store instance
        
    Returns:
        Result with updated Store or error message
    """
    # Read existing inventory
    inventory_result = read_inventory(store)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")
    
    inventory = inventory_result.unwrap()
    
    # Update CA certificate information if it exists
    ca_cert_result = read_ca_cert(store)
    if ca_cert_result:
        inventory.ca = CAInventoryEntry.from_certificate(ca_cert_result.unwrap())
    
    # Update host certificates information
    store_path = Path(store.path)
    hosts_dir = get_hosts_dir(store_path)
    
    if hosts_dir.exists():
        # Get all host directories
        host_dirs = [d for d in hosts_dir.iterdir() if d.is_dir()]
        
        for host_dir in host_dirs:
            host_id = host_dir.name
            cert_path = get_host_cert_path(store_path, host_id)
            
            if cert_path.exists():
                # Read host certificate
                host_cert_result = read_host_cert(store, host_id)
                if host_cert_result:
                    cert = host_cert_result.unwrap()
                    
                    # Find existing host entry or create new one
                    for i, host in enumerate(inventory.hosts):
                        if host.short_name == host_id:
                            # Update existing entry
                            inventory.hosts[i] = InventoryEntry.from_certificate(host_id, cert)
                            # Preserve renewal and rekey counts
                            inventory.hosts[i].renewal_count = host.renewal_count
                            inventory.hosts[i].rekey_count = host.rekey_count
                            break
                    else:
                        # Add new entry
                        inventory.hosts.append(InventoryEntry.from_certificate(host_id, cert))
    
    # Write updated inventory
    return write_inventory(store, inventory)


def update_host_in_inventory(
    store: Store, 
    host_id: str, 
    cert: x509.Certificate, 
    rekeyed: bool = False,
    renewal_count_increment: int = 1,
) -> Result[Store, str]:
    """
    Update a host entry in the inventory.
    
    Args:
        store: Store instance
        host_id: Host identifier
        cert: Certificate to update inventory with
        rekeyed: Whether the certificate was rekeyed
        renewal_count_increment: Amount to increment renewal count
        
    Returns:
        Result with updated Store or error message
    """
    # Read existing inventory
    inventory_result = read_inventory(store)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")
    
    inventory = inventory_result.unwrap()
    
    # Find existing host entry or create new one
    for i, host in enumerate(inventory.hosts):
        if host.short_name == host_id:
            # Update existing entry with new certificate info
            updated_entry = InventoryEntry.from_certificate(host_id, cert)
            # Preserve and increment counts
            updated_entry.renewal_count = host.renewal_count + renewal_count_increment
            updated_entry.rekey_count = host.rekey_count + (1 if rekeyed else 0)
            inventory.hosts[i] = updated_entry
            break
    else:
        # Add new entry
        new_entry = InventoryEntry.from_certificate(host_id, cert)
        new_entry.renewal_count = renewal_count_increment
        new_entry.rekey_count = 1 if rekeyed else 0
        inventory.hosts.append(new_entry)
    
    # Write updated inventory
    return write_inventory(store, inventory)


def ca_exists(store: Store) -> bool:
    """
    Check if a CA exists in the store.
    
    Args:
        store: Store instance
        
    Returns:
        True if CA certificate and key exist, False otherwise
    """
    store_path = Path(store.path)
    return (
        get_ca_cert_path(store_path).exists() and
        get_ca_key_path(store_path).exists()
    )


def host_exists(store: Store, host_id: str) -> bool:
    """
    Check if a host exists in the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        
    Returns:
        True if host certificate exists, False otherwise
    """
    return get_host_cert_path(Path(store.path), host_id).exists()


def list_hosts(store: Store) -> Result[list[str], str]:
    """
    List all hosts in the store, sorted alphabetically.
    
    Args:
        store: Store instance
        
    Returns:
        Result with list of host identifiers or error message
    """
    store_path = Path(store.path)
    hosts_dir = get_hosts_dir(store_path)
    
    if not hosts_dir.exists():
        return Success([])
    
    try:
        # Get all subdirectories in the hosts directory
        host_ids = [d.name for d in hosts_dir.iterdir() if d.is_dir()]
        # Sort alphabetically
        host_ids.sort()
        return Success(host_ids)
    except Exception as e:
        return Failure(f"Failed to list hosts: {str(e)}")


def delete_host(store: Store, host_id: str) -> Result[Store, str]:
    """
    Delete a host from the store.
    
    Args:
        store: Store instance
        host_id: Host identifier
        
    Returns:
        Result with updated Store or error message
    """
    store_path = Path(store.path)
    host_dir = get_host_dir(store_path, host_id)
    
    if not host_dir.exists():
        return Failure(f"Host directory for {host_id} not found at {host_dir}")
    
    try:
        # Delete certificate and key
        cert_path = get_host_cert_path(store_path, host_id)
        key_path = get_host_key_path(store_path, host_id)
        
        if cert_path.exists():
            cert_path.unlink()
            logger.info(f"Deleted certificate for {host_id}")
        
        if key_path.exists():
            key_path.unlink()
            logger.info(f"Deleted private key for {host_id}")
        
        # Try to remove the directory if it's empty
        try:
            host_dir.rmdir()
            logger.info(f"Removed host directory for {host_id}")
        except OSError:
            # Directory not empty, that's OK
            pass
        
        # Update inventory to remove the host
        inventory_result = read_inventory(store)
        if not inventory_result:
            return Failure(f"Failed to read inventory: {inventory_result.error}")
        
        inventory = inventory_result.unwrap()
        
        # Remove host from inventory
        inventory.hosts = [host for host in inventory.hosts if host.short_name != host_id]
        
        # Write updated inventory
        write_result = write_inventory(store, inventory)
        if not write_result:
            return Failure(f"Failed to update inventory: {write_result.error}")
        
        return Success(write_result.unwrap())
    except Exception as e:
        return Failure(f"Failed to delete host {host_id}: {str(e)}")


def get_host_info(store: Store, host_id: str) -> Result[dict[str, Any], str]:
    """
    Get certificate information for a host.
    
    Args:
        store: Store instance
        host_id: Host identifier
        
    Returns:
        Result with host info dictionary or error message
    """
    # Read inventory
    inventory_result = read_inventory(store)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")
    
    inventory = inventory_result.unwrap()
    
    # Find host in inventory
    for host in inventory.hosts:
        if host.short_name == host_id:
            # Convert to dictionary
            host_info = {
                "name": host.short_name,
                "serial": host.serial,
                "not_before": host.not_before.isoformat(),
                "not_after": host.not_after.isoformat(),
                "fingerprint": host.fingerprint_sha256,
                "renewal_count": host.renewal_count,
                "rekey_count": host.rekey_count,
            }
            
            # Add additional details from certificate if available
            cert_result = read_host_cert(store, host_id)
            if cert_result:
                cert = cert_result.unwrap()
                
                # Calculate days until expiry
                now = datetime.datetime.now(datetime.UTC)
                expiry = cert.not_valid_after
                delta = expiry - now
                
                host_info["days_until_expiry"] = delta.days
                
                # Add subject information
                subject = cert.subject
                host_info["subject"] = {}
                
                for attr in subject:
                    host_info["subject"][attr.oid._name] = attr.value
            
            return Success(host_info)
    
    return Failure(f"Host {host_id} not found in inventory")


def export_ca_cert(store: Store, export_path: Path) -> Result[None, str]:
    """
    Export the CA certificate to the specified path.
    
    Args:
        store: Store instance
        export_path: Path to export certificate to
        
    Returns:
        Result with None or error message
    """
    # Read CA certificate
    ca_cert_result = read_ca_cert(store)
    if not ca_cert_result:
        return Failure(f"Failed to read CA certificate: {ca_cert_result.error}")
    
    cert = ca_cert_result.unwrap()
    
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


def export_host_cert(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """
    Export a host certificate to the specified path.
    
    Args:
        store: Store instance
        host_id: Host identifier
        export_path: Path to export certificate to
        
    Returns:
        Result with None or error message
    """
    # Read host certificate
    host_cert_result = read_host_cert(store, host_id)
    if not host_cert_result:
        return Failure(f"Failed to read host certificate: {host_cert_result.error}")
    
    cert = host_cert_result.unwrap()
    
    try:
        # Ensure parent directory exists
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write certificate to export path
        cert_bytes = cert.public_bytes(Encoding.PEM)
        with open(export_path, "wb") as f:
            f.write(cert_bytes)
        
        logger.info(f"Exported certificate for {host_id} to {export_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export certificate for {host_id}: {str(e)}")


def export_host_key_unencrypted(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """
    Export an unencrypted host private key to the specified path.
    
    Args:
        store: Store instance
        host_id: Host identifier
        export_path: Path to export key to
        
    Returns:
        Result with None or error message
    """
    # Check if store is unlocked
    unlocked_result = require_unlocked(store)
    if not unlocked_result:
        return Failure(unlocked_result.error)
    
    # Read host key
    host_key_result = read_host_key(store, host_id)
    if not host_key_result:
        return Failure(f"Failed to read host key: {host_key_result.error}")
    
    key = host_key_result.unwrap()
    
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
        
        logger.info(f"Exported unencrypted private key for {host_id} to {export_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export private key for {host_id}: {str(e)}")


def export_host_chain(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """
    Export a host certificate chain (host + CA certs) to the specified path.
    
    Args:
        store: Store instance
        host_id: Host identifier
        export_path: Path to export certificate chain to
        
    Returns:
        Result with None or error message
    """
    # Read host certificate
    host_cert_result = read_host_cert(store, host_id)
    if not host_cert_result:
        return Failure(f"Failed to read host certificate: {host_cert_result.error}")
    
    host_cert = host_cert_result.unwrap()
    
    # Read CA certificate
    ca_cert_result = read_ca_cert(store)
    if not ca_cert_result:
        return Failure(f"Failed to read CA certificate: {ca_cert_result.error}")
    
    ca_cert = ca_cert_result.unwrap()
    
    try:
        # Ensure parent directory exists
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write host certificate followed by CA certificate
        host_cert_bytes = host_cert.public_bytes(Encoding.PEM)
        ca_cert_bytes = ca_cert.public_bytes(Encoding.PEM)
        
        with open(export_path, "wb") as f:
            f.write(host_cert_bytes)
            f.write(ca_cert_bytes)
        
        logger.info(f"Exported certificate chain for {host_id} to {export_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to export certificate chain for {host_id}: {str(e)}")


def change_password(
    store: Store, 
    old_password: str | None = None, 
    new_password: str | None = None,
) -> Result[Store, str]:
    """
    Change the password for all private keys in the store.
    
    Args:
        store: Store instance
        old_password: Optional current password
        new_password: Optional new password
        
    Returns:
        Result with updated Store or error message
    """
    # Check if store is unlocked or try to unlock with old_password
    if not store.unlocked or not store.password:
        if old_password:
            # Try to unlock with provided old password
            unlock_result = unlock_store(store, password=old_password)
            if not unlock_result:
                return Failure(f"Current password is incorrect: {unlock_result.error}")
            store = unlock_result.unwrap()
        else:
            # Prompt for old password
            config_path, store_path = resolve_paths(None, store.path)
            try:
                ca_config = load_ca_config(get_ca_config_path(config_path))
                min_length = ca_config.password.min_length
            except Exception:
                min_length = 8
            
            old_password_result = get_password(
                store=store,
                min_length=min_length,
                prompt_message="Enter current password: ",
            )
            
            if not old_password_result:
                return Failure(f"Failed to get current password: {old_password_result.error}")
            
            old_password = old_password_result.unwrap()
            
            # Try to unlock with this password
            unlock_result = unlock_store(store, password=old_password)
            if not unlock_result:
                return Failure(f"Current password is incorrect: {unlock_result.error}")
            store = unlock_result.unwrap()
    
    # Get new password if not provided
    config_path, store_path = resolve_paths(None, store.path)
    try:
        ca_config = load_ca_config(get_ca_config_path(config_path))
        min_length = ca_config.password.min_length
    except Exception:
        min_length = 8
    
    if not new_password:
        new_password_result = get_password(
            store=store,
            min_length=min_length,
            prompt_message="Enter new password: ",
            confirm=True,
        )
        
        if not new_password_result:
            return Failure(f"Failed to get new password: {new_password_result.error}")
        
        new_password = new_password_result.unwrap()
    
    # Verify new password
    verify_result = verify_password(new_password, min_length=min_length)
    if not verify_result:
        return Failure(verify_result.error)
    
    # Find all encrypted key files
    encrypted_key_files = []
    
    # CA key
    ca_key_path = get_ca_key_path(store_path)
    if ca_key_path.exists():
        encrypted_key_files.append((ca_key_path, None))  # None indicates CA key
    
    # Host keys
    hosts_dir = get_hosts_dir(store_path)
    if hosts_dir.exists():
        for host_dir in [d for d in hosts_dir.iterdir() if d.is_dir()]:
            host_id = host_dir.name
            key_path = get_host_key_path(store_path, host_id)
            if key_path.exists():
                encrypted_key_files.append((key_path, host_id))
    
    if not encrypted_key_files:
        return Failure("No encrypted key files found")
    
    try:
        # Process each key file
        for key_path, host_id in encrypted_key_files:
            # Read encrypted key
            with open(key_path, "rb") as f:
                encrypted_key_data = f.read()
            
            # Decrypt with old password
            private_key = load_pem_private_key(
                encrypted_key_data,
                password=store.password.encode(),
            )
            
            # Re-encrypt with new password
            new_encrypted_data = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(new_password.encode()),
            )
            
            # Write updated key
            with open(key_path, "wb") as f:
                f.write(new_encrypted_data)
            
            if host_id:
                CONSOLE.print(f"✅ Re-encrypted key for {host_id}")
            else:
                CONSOLE.print("✅ Re-encrypted CA key")
        
        # Update password for session
        new_store = Store(
            path=store.path,
            password=new_password,
            unlocked=True,
        )
        
        CONSOLE.print(f"\n✅ Changed password for {len(encrypted_key_files)} key files")
        return Success(new_store)
    except Exception as e:
        return Failure(f"Failed to change password: {str(e)}")


def get_cert_expiry_days(store: Store, host_id: str | None = None) -> Result[int, str]:
    """
    Get the expiry date of a certificate in days from now.
    
    Args:
        store: Store instance
        host_id: Host identifier, or None for CA certificate
        
    Returns:
        Result with days until expiry or error message
    """
    # Read certificate based on whether it's a host or CA
    if host_id:
        cert_result = read_host_cert(store, host_id)
        if not cert_result:
            return Failure(f"Failed to read host certificate: {cert_result.error}")
    else:
        cert_result = read_ca_cert(store)
        if not cert_result:
            return Failure(f"Failed to read CA certificate: {cert_result.error}")
    
    cert = cert_result.unwrap()
    
    # Calculate days until expiry
    now = datetime.datetime.now(datetime.UTC)
    expiry = cert.not_valid_after
    delta = expiry - now
    
    return Success(delta.days)