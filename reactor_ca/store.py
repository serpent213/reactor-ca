"""Certificate Store Management.

This module provides functions for managing certificate storage
and file operations for the ReactorCA tool.
"""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from rich.console import Console

from reactor_ca.models import Store
from reactor_ca.paths import (
    get_store_ca_cert_path,
    get_store_ca_dir,
    get_store_ca_key_path,
    get_store_host_cert_path,
    get_store_host_dir,
    get_store_host_key_path,
    get_store_hosts_dir,
)
from reactor_ca.result import Failure, Result, Success
from reactor_ca.x509_crypto import (
    deserialize_certificate,
    deserialize_private_key,
    serialize_certificate,
    serialize_private_key,
)

# Module-level console instance
# TODO
CONSOLE = Console()


def create(path: Path) -> Result[Store, str]:
    """Create a new store at the specified path.

    This creates the directory structure and returns a Store object.

    Args:
    ----
        path: Path to store directory

    Returns:
    -------
        Result with initialized Store instance or error message

    """
    try:
        store = Store(path=path)

        # Create required directory structure
        path.mkdir(parents=True, exist_ok=True)
        get_store_ca_dir(store).mkdir(parents=True, exist_ok=True)
        get_store_hosts_dir(store).mkdir(parents=True, exist_ok=True)

        return Success(store)
    except Exception as e:
        return Failure(f"Failed to create store: {str(e)}")


def init(path: Path) -> Result[Store, str]:
    """Initialize a Store from an existing store path.

    This checks that directories exist and returns a Store object.

    Args:
    ----
        path: Path to the existing store directory

    Returns:
    -------
        Result with Store object or error message

    """
    try:
        # Verify this is an existing, valid store
        store_dir = Path(path)
        ca_dir = get_store_ca_dir(store_dir)
        hosts_dir = get_store_hosts_dir(store_dir)

        if not store_dir.exists():
            return Failure(f"Store directory does not exist: {store_dir}")

        if not ca_dir.exists():
            return Failure(f"CA directory does not exist: {ca_dir}")

        if not hosts_dir.exists():
            return Failure(f"Hosts directory does not exist: {hosts_dir}")

        store = Store(path=path)
        return Success(store)
    except Exception as e:
        return Failure(f"Failed to initialize from existing store: {str(e)}")


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
    key_present, _cert_present = check_ca_files(store)

    if not key_present:
        return Failure("CA not initialised")

    # Create a temporary store with the password for validation
    maybe_unlocked_store = Store(path=store.path, password=password, unlocked=True)

    # If CA exists, validate password by trying to load the CA key
    key_result = read_ca_key(maybe_unlocked_store)
    if isinstance(key_result, Failure):
        return Failure(f"Invalid password: {key_result.error}")

    # Password is valid
    return Success(maybe_unlocked_store)


def read_ca_cert(store: Store) -> Result[x509.Certificate, str]:
    """Read the CA certificate from the store.

    Args:
    ----
        store: Store object

    Returns:
    -------
        Result with certificate object or error message

    """
    cert_path = get_store_ca_cert_path(store)

    if not cert_path.exists():
        return Failure(f"CA certificate not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        return deserialize_certificate(cert_data)
    except Exception as e:
        return Failure(f"Failed to load CA certificate: {str(e)}")


def write_ca_cert(store: Store, cert: x509.Certificate) -> Result[None, str]:
    """Write the CA certificate to the store.

    Args:
    ----
        store: Store object
        cert: Certificate object to write

    Returns:
    -------
        Result with None for success or error message

    """
    cert_path = get_store_ca_cert_path(store)

    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize and write certificate
        cert_bytes_result = serialize_certificate(cert)
        if isinstance(cert_bytes_result, Failure):
            return cert_bytes_result

        cert_bytes = cert_bytes_result.unwrap()
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write CA certificate: {str(e)}")


def read_ca_key(store: Store) -> Result[PrivateKeyTypes, str]:
    """Read the CA private key from the store.

    Args:
    ----
        store: Store object with password

    Returns:
    -------
        Result with private key object or error message

    """
    key_path = get_store_ca_key_path(store)

    if not key_path.exists():
        return Failure(f"CA private key not found at {key_path}")

    if not store.unlocked:
        return Failure("Store not unlocked")

    try:
        with open(key_path, "rb") as f:
            key_data = f.read()

        # Decrypt if needed (password is already utf-8 encoded)
        return deserialize_private_key(key_data, store.password)
    except Exception as e:
        return Failure(f"Failed to load CA private key: {str(e)}")


def write_ca_key(store: Store, key: PrivateKeyTypes) -> Result[None, str]:
    """Write the CA private key to the store.

    Args:
    ----
        store: Store object with password
        key: Private key object to write

    Returns:
    -------
        Result with None for success or error message

    """
    key_path = get_store_ca_key_path(store)

    if not store.unlocked:
        return Failure("Store not unlocked")

    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Encrypt with password if available (password is already utf-8 encoded)
        key_bytes_result = serialize_private_key(key, store.password)
        if isinstance(key_bytes_result, Failure):
            return key_bytes_result

        key_bytes = key_bytes_result.unwrap()
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write CA private key: {str(e)}")


def host_exists(store: Store, host_id: str) -> bool:
    """Check if a host exists in the store.

    Args:
    ----
        store: Store object
        host_id: Host identifier

    Returns:
    -------
        True if host certificate exists, False otherwise

    """
    cert_path = get_store_host_cert_path(store, host_id)
    return cert_path.exists()


def read_host_cert(store: Store, host_id: str) -> Result[x509.Certificate, str]:
    """Read a host certificate from the store.

    Args:
    ----
        store: Store object
        host_id: Host identifier

    Returns:
    -------
        Result with certificate object or error message

    """
    cert_path = get_store_host_cert_path(store, host_id)

    if not cert_path.exists():
        return Failure(f"Certificate for {host_id} not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        return deserialize_certificate(cert_data)
    except Exception as e:
        return Failure(f"Failed to load certificate for {host_id}: {str(e)}")


def write_host_cert(store: Store, host_id: str, cert: x509.Certificate) -> Result[None, str]:
    """Write a host certificate to the store.

    Args:
    ----
        store: Store object
        host_id: Host identifier
        cert: Certificate object to write

    Returns:
    -------
        Result with None for success or error message

    """
    cert_path = get_store_host_cert_path(store, host_id)

    try:
        # Ensure parent directory exists
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize and write certificate
        cert_bytes_result = serialize_certificate(cert)
        if isinstance(cert_bytes_result, Failure):
            return cert_bytes_result

        cert_bytes = cert_bytes_result.unwrap()
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write certificate for {host_id}: {str(e)}")


def read_host_key(store: Store, host_id: str) -> Result[PrivateKeyTypes, str]:
    """Read the host private key from the store.

    Args:
    ----
        store: Store object with password
        host_id: Host identifier

    Returns:
    -------
        Result with private key object or error message

    """
    key_path = get_store_host_key_path(store, host_id)

    if not key_path.exists():
        return Failure(f"Private key for {host_id} not found at {key_path}")

    if not store.unlocked:
        return Failure("Store not unlocked")

    try:
        with open(key_path, "rb") as f:
            key_data = f.read()

        # Decrypt if needed (password is already utf-8 encoded)
        return deserialize_private_key(key_data, store.password)
    except Exception as e:
        return Failure(f"Failed to load private key for {host_id}: {str(e)}")


def write_host_key(store: Store, host_id: str, key: PrivateKeyTypes) -> Result[None, str]:
    """Write the host private key to the store.

    Args:
    ----
        store: Store object with password
        host_id: Host identifier
        key: Private key object to write

    Returns:
    -------
        Result with None for success or error message

    """
    key_path = get_store_host_key_path(store, host_id)

    if not store.unlocked:
        return Failure("Store not unlocked")

    try:
        # Ensure parent directory exists
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Encrypt with password if available (password is already utf-8 encoded)
        key_bytes_result = serialize_private_key(key, store.password)
        if isinstance(key_bytes_result, Failure):
            return key_bytes_result

        key_bytes = key_bytes_result.unwrap()
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write private key for {host_id}: {str(e)}")


def list_hosts(store: Store) -> Result[list[str], str]:
    """List all hosts in the store, sorted alphabetically.

    Args:
    ----
        store: Store object

    Returns:
    -------
        Result with list of host identifiers or error message

    """
    hosts_dir = get_store_hosts_dir(store)

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


def delete_host(store: Store, host_id: str) -> Result[None, str]:
    """Delete a host's files from the store.

    Args:
    ----
        store: Store object
        host_id: Host identifier

    Returns:
    -------
        Result with None for success or error message

    """
    host_dir = get_store_host_dir(store, host_id)

    if not host_dir.exists():
        return Failure(f"Host directory for {host_id} not found at {host_dir}")

    try:
        # Delete certificate and key
        cert_path = get_store_host_cert_path(store, host_id)
        key_path = get_store_host_key_path(store, host_id)

        if cert_path.exists():
            cert_path.unlink()

        if key_path.exists():
            key_path.unlink()

        # Try to remove the directory if it's empty
        try:
            host_dir.rmdir()
        except OSError:
            # Directory not empty, that's OK
            pass

        return Success(None)
    except Exception as e:
        return Failure(f"Failed to delete host {host_id}: {str(e)}")


def change_password(store: Store, new_password: str) -> Result[Store, str]:
    """Change the password for all private keys in the store.

    Args:
    ----
        store: Store object with current password
        new_password: New password

    Returns:
    -------
        Result with updated Store with new password or error message

    """
    if not store.unlocked or not store.password:
        return Failure("Store not unlocked - current password required")

    # Find all encrypted key files
    key_files: list[tuple[Path, str | None]] = []

    # CA key
    ca_key_path = get_store_ca_key_path(store)
    if ca_key_path.exists():
        key_files.append((ca_key_path, None))  # None indicates CA key

    # Host keys
    hosts_dir = get_store_hosts_dir(store)
    if hosts_dir.exists():
        for host_dir in [d for d in hosts_dir.iterdir() if d.is_dir()]:
            host_id = host_dir.name
            key_path = get_store_host_key_path(store, host_id)
            if key_path.exists():
                key_files.append((key_path, host_id))

    if not key_files:
        return Failure("No key files found")

    try:
        # Process each key file
        for _, current_host_id in key_files:
            # Read the key (automatically decrypted with store.password)
            if current_host_id is None:
                # CA key
                key_result = read_ca_key(store)
            else:
                # Host key
                key_result = read_host_key(store, current_host_id)

            if isinstance(key_result, Failure):
                return key_result

            private_key = key_result.unwrap()

            # Create a temporary store with the new password
            new_store = Store(path=store.path, password=new_password, unlocked=True)

            # Write the key with the new password
            if current_host_id is None:
                write_result = write_ca_key(new_store, private_key)
            else:
                write_result = write_host_key(new_store, current_host_id, private_key)

            if isinstance(write_result, Failure):
                return write_result

            if current_host_id:
                CONSOLE.print(f"✅ Re-encrypted key for {current_host_id}")
            else:
                CONSOLE.print("✅ Re-encrypted CA key")

        CONSOLE.print(f"\n✅ Changed password for {len(key_files)} key files")

        # Return updated store with new password
        return Success(Store(path=store.path, password=new_password, unlocked=True))
    except Exception as e:
        return Failure(f"Failed to change password: {str(e)}")


def check_ca_files(store: Store) -> tuple[bool, bool]:
    """Check if CA key and certificate files exist.

    Args:
    ----
        store: Store object

    Returns:
    -------
        Tuple where first bool is True if key file exists, second bool
        is True if cert file exists

    """
    key_path = get_store_ca_key_path(store)
    cert_path = get_store_ca_cert_path(store)

    return (key_path.exists(), cert_path.exists())


def check_host_files(store: Store, hostname: str) -> tuple[bool, bool]:
    """Check if host key and certificate files exist.

    Args:
    ----
        store: Store object
        hostname: Host identifier

    Returns:
    -------
        Tuple where first bool is True if key file exists, second bool
        is True if cert file exists

    """
    key_path = get_store_host_key_path(store, hostname)
    cert_path = get_store_host_cert_path(store, hostname)

    return (key_path.exists(), cert_path.exists())
