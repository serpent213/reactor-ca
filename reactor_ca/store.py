"""Certificate Store Management.

This module provides low-level functions for managing certificate storage 
and file operations for the ReactorCA tool.
"""

import logging
from pathlib import Path
from typing import Any, Union, TypeVar, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from rich.console import Console

from reactor_ca.models import Config, Store
from reactor_ca.paths import (
    ensure_dirs,
    get_ca_cert_path,
    get_ca_key_path,
    get_host_cert_path,
    get_host_dir,
    get_host_key_path,
    get_hosts_dir,
    resolve_paths,
)
from reactor_ca.result import Failure, Result, Success

# Type for our normalized config helper
T = TypeVar('T')

# Module-level console instance
CONSOLE = Console()

# Setup logging
logger = logging.getLogger(__name__)


def normalize_to_config(config_or_store: Union[Config, Store, str]) -> Result[Config, str]:
    """Normalize various input types to a Config object.
    
    Args:
    ----
        config_or_store: A Config object, Store object, or path string
        
    Returns:
    -------
        Result containing a Config object or error message
    """
    try:
        # Extract Config object
        if isinstance(config_or_store, Store):
            return Success(Config(
                config_path="",
                store_path=config_or_store.path,
                ca_config=None,  # type: ignore
                hosts_config={}  # type: ignore
            ))
        elif isinstance(config_or_store, Config):
            return Success(config_or_store) 
        elif isinstance(config_or_store, str):
            # Legacy support for path string
            return Success(Config(
                config_path="",
                store_path=config_or_store,
                ca_config=None,  # type: ignore
                hosts_config={}  # type: ignore
            ))
        else:
            return Failure(f"Unsupported argument type: {type(config_or_store)}")
    except Exception as e:
        return Failure(f"Error normalizing input to Config: {str(e)}")


def create_store(config_dir: str | None = None, store_dir: str | None = None) -> Store:
    """Create a new Store instance with the specified or default paths.

    Args:
    ----
        config_dir: Optional path to configuration directory
        store_dir: Optional path to store directory

    Returns:
    -------
        Initialized Store instance

    """
    _config_path, store_path = resolve_paths(config_dir, store_dir)
    return Store(path=str(store_path))


def unlock(store: Store, password: str) -> Result[Store, str]:
    """Unlock a store with the provided password.
    
    Args:
    ----
        store: Store to unlock
        password: Password to unlock the store
        
    Returns:
    -------
        Result with updated unlocked Store or error
    """
    # If store is already unlocked, just return it
    if store.unlocked and store.password:
        return Success(store)
    
    # If CA exists, validate password by trying to load the CA key
    if ca_exists(store.path):
        key_result = read_ca_key(store.path, password)
        if not key_result:  # Using boolean conversion
            return Failure(f"Invalid password: {key_result.error}")
    
    # Update store with password and mark as unlocked
    # Since Store isn't frozen, we can modify it directly
    store.password = password
    store.unlocked = True
    return Success(store)


def initialize_store(store_path: str) -> Result[None, str]:
    """Initialize the store directory structure.

    Args:
    ----
        store_path: Path to the store directory

    Returns:
    -------
        Result with None for success or error message

    Note:
    ----
        This function is a legacy entry point that still accepts a path string.
        It creates a minimal Config object to use with ensure_dirs.

    """
    try:
        config_path, store_path_obj = resolve_paths(None, store_path)
        
        # Create a minimal Config for initialize_store
        from reactor_ca.models import Config
        temp_config = Config(
            config_path=str(config_path),
            store_path=str(store_path_obj),
            ca_config=None,  # type: ignore
            hosts_config={}  # type: ignore
        )
        
        ensure_dirs(temp_config)
        logger.info(f"Initialized certificate store at {store_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to initialize store: {str(e)}")


def read_ca_cert(config_or_store: Union[Config, Store, str]) -> Result[bytes, str]:
    """Read the CA certificate from the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string

    Returns:
    -------
        Result with certificate bytes or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    cert_path = get_ca_cert_path(config)
    
    if not cert_path.exists():
        return Failure(f"CA certificate not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        logger.debug(f"Loaded CA certificate from {cert_path}")
        return Success(cert_data)
    except Exception as e:
        return Failure(f"Failed to load CA certificate: {str(e)}")


def write_ca_cert(config_or_store: Union[Config, Store, str], cert_bytes: bytes) -> Result[None, str]:
    """Write the CA certificate to the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        cert_bytes: Certificate bytes to write

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    cert_path = get_ca_cert_path(config)

    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Saved CA certificate to {cert_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write CA certificate: {str(e)}")


def read_ca_key(config_or_store: Union[Config, Store, str], password: str) -> Result[bytes, str]:
    """Read the encrypted CA private key from the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        password: Password to decrypt the key

    Returns:
    -------
        Result with private key bytes or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    key_path = get_ca_key_path(config)
    
    if not key_path.exists():
        return Failure(f"CA private key not found at {key_path}")

    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
            # Verify the password works
            load_pem_private_key(key_data, password.encode("utf-8"))

        logger.debug(f"Loaded CA private key from {key_path}")
        return Success(key_data)
    except Exception as e:
        return Failure(f"Failed to load CA private key: {str(e)}")


def write_ca_key(config_or_store: Union[Config, Store, str], key_bytes: bytes, password: str) -> Result[None, str]:
    """Write the encrypted CA private key to the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        key_bytes: Private key bytes to write
        password: Password to encrypt the key

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    key_path = get_ca_key_path(config)

    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Ensure we have a private key in the right format
        key = load_pem_private_key(key_bytes, None)

        # Encrypt with password
        encryption = BestAvailableEncryption(password.encode("utf-8"))
        encrypted_key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

        # Write key
        with open(key_path, "wb") as f:
            f.write(encrypted_key_bytes)

        logger.info(f"Saved encrypted CA private key to {key_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write CA private key: {str(e)}")


def read_host_cert(config_or_store: Union[Config, Store, str], host_id: str) -> Result[bytes, str]:
    """Read a host certificate from the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier

    Returns:
    -------
        Result with certificate bytes or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    cert_path = get_host_cert_path(config, host_id)
    
    if not cert_path.exists():
        return Failure(f"Certificate for {host_id} not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        logger.debug(f"Loaded certificate for {host_id} from {cert_path}")
        return Success(cert_data)
    except Exception as e:
        return Failure(f"Failed to load certificate for {host_id}: {str(e)}")


def write_host_cert(config_or_store: Union[Config, Store, str], host_id: str, cert_bytes: bytes) -> Result[None, str]:
    """Write a host certificate to the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier
        cert_bytes: Certificate bytes to write

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    cert_path = get_host_cert_path(config, host_id)

    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Saved certificate for {host_id} to {cert_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write certificate for {host_id}: {str(e)}")


def read_host_key(config_or_store: Union[Config, Store, str], host_id: str, password: str) -> Result[bytes, str]:
    """Read the encrypted host private key from the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier
        password: Password to decrypt the key

    Returns:
    -------
        Result with private key bytes or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    key_path = get_host_key_path(config, host_id)
    
    if not key_path.exists():
        return Failure(f"Private key for {host_id} not found at {key_path}")

    try:
        with open(key_path, "rb") as f:
            key_data = f.read()
            # Verify the password works
            load_pem_private_key(key_data, password.encode("utf-8"))

        logger.debug(f"Loaded private key for {host_id} from {key_path}")
        return Success(key_data)
    except Exception as e:
        return Failure(f"Failed to load private key for {host_id}: {str(e)}")


def write_host_key(config_or_store: Union[Config, Store, str], host_id: str, key_bytes: bytes, password: str) -> Result[None, str]:
    """Write the encrypted host private key to the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier
        key_bytes: Private key bytes to write
        password: Password to encrypt the key

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    key_path = get_host_key_path(config, host_id)

    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Ensure we have a private key in the right format
        key = load_pem_private_key(key_bytes, None)

        # Encrypt with password
        encryption = BestAvailableEncryption(password.encode("utf-8"))
        encrypted_key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

        # Write key
        with open(key_path, "wb") as f:
            f.write(encrypted_key_bytes)

        logger.info(f"Saved encrypted private key for {host_id} to {key_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write private key for {host_id}: {str(e)}")


def ca_exists(config_or_store: Union[Config, Store, str]) -> bool:
    """Check if a CA exists in the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string

    Returns:
    -------
        True if CA certificate and key exist, False otherwise

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        # If we can't normalize, we can be sure CA doesn't exist
        return False
    
    config = config_result.value
    return get_ca_cert_path(config).exists() and get_ca_key_path(config).exists()


def host_exists(config_or_store: Union[Config, Store, str], host_id: str) -> bool:
    """Check if a host exists in the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier

    Returns:
    -------
        True if host certificate exists, False otherwise

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        # If we can't normalize, we can be sure host doesn't exist
        return False
    
    config = config_result.value
    return get_host_cert_path(config, host_id).exists()


def list_hosts(config_or_store: Union[Config, Store, str]) -> Result[list[str], str]:
    """List all hosts in the store, sorted alphabetically.

    Args:
    ----
        config_or_store: Config object, Store object, or path string

    Returns:
    -------
        Result with list of host identifiers or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    hosts_dir = get_hosts_dir(config)

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


def delete_host(config_or_store: Union[Config, Store, str], host_id: str) -> Result[None, str]:
    """Delete a host's files from the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        host_id: Host identifier

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    host_dir = get_host_dir(config, host_id)

    if not host_dir.exists():
        return Failure(f"Host directory for {host_id} not found at {host_dir}")

    try:
        # Delete certificate and key
        cert_path = get_host_cert_path(config, host_id)
        key_path = get_host_key_path(config, host_id)

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

        return Success(None)
    except Exception as e:
        return Failure(f"Failed to delete host {host_id}: {str(e)}")


def change_password(config_or_store: Union[Config, Store, str], old_password: str, new_password: str) -> Result[None, str]:
    """Change the password for all private keys in the store.

    Args:
    ----
        config_or_store: Config object, Store object, or path string
        old_password: Current password
        new_password: New password

    Returns:
    -------
        Result with None for success or error message

    """
    # Normalize input to Config object
    config_result = normalize_to_config(config_or_store)
    if not config_result:
        return Failure(config_result.error)
    
    config = config_result.value
    
    # Find all encrypted key files
    encrypted_key_files = []

    # CA key
    ca_key_path = get_ca_key_path(config)
    if ca_key_path.exists():
        encrypted_key_files.append((ca_key_path, None))  # None indicates CA key

    # Host keys
    hosts_dir = get_hosts_dir(config)
    if hosts_dir.exists():
        for host_dir in [d for d in hosts_dir.iterdir() if d.is_dir()]:
            host_id = host_dir.name
            key_path = get_host_key_path(config, host_id)
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
                password=old_password.encode(),
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

        CONSOLE.print(f"\n✅ Changed password for {len(encrypted_key_files)} key files")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to change password: {str(e)}")