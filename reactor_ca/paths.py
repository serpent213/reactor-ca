"""Path management for ReactorCA."""

from pathlib import Path
from typing import overload

from reactor_ca.defaults import DEFAULT_DIR_ROOT, DEFAULT_SUBDIR_CONFIG, DEFAULT_SUBDIR_STORE
from reactor_ca.models import Config, Store

# Schema directory is always relative to the code, not user configuration
SCHEMAS_DIR = Path(__file__).parent / "schemas"


def resolve_paths(
    root_dir: Path | None = None,
    config_dir: Path | None = None,
    store_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Resolve configuration and store paths.

    The resolution order is:
    1. Explicitly provided arguments
    2. Default values (current directory with standard subdirectories)

    Args:
    ----
        root_dir: Optional root directory (used if config_dir or store_dir not provided)
        config_dir: Optional path to configuration directory
        store_dir: Optional path to store directory

    Returns:
    -------
        Tuple of (config_dir, store_dir) as Path objects

    """
    root = root_dir if root_dir else DEFAULT_DIR_ROOT
    config = config_dir if config_dir else Path(root) / DEFAULT_SUBDIR_CONFIG
    store = store_dir if store_dir else Path(root) / DEFAULT_SUBDIR_STORE
    return config, store


# Helper functions for path construction


def _get_store_path(store_or_path: Path | Store) -> Path:
    """Extract store path from Path or Store object.

    Args:
    ----
        store_or_path: Path object or Store object

    Returns:
    -------
        Store path as a Path object

    """
    if isinstance(store_or_path, Path):
        return store_or_path
    elif isinstance(store_or_path, Store):
        return store_or_path.path
    else:
        raise TypeError(f"Expected Path or Store, got {type(store_or_path)}")


def _get_config_path(config_or_path: Path | Config) -> Path:
    """Extract config path from Path or Config object.

    Args:
    ----
        config_or_path: Path object or Config object

    Returns:
    -------
        Config path as a Path object

    """
    if isinstance(config_or_path, Path):
        return config_or_path
    elif isinstance(config_or_path, Config):
        return config_or_path.config_path
    else:
        raise TypeError(f"Expected Path or Config, got {type(config_or_path)}")


# Config directory functions


@overload
def get_ca_config_path(config_or_path: Config) -> Path:
    ...


@overload
def get_ca_config_path(config_or_path: Path) -> Path:
    ...


def get_ca_config_path(config_or_path: Path | Config) -> Path:
    """Get the CA config file path.

    Args:
    ----
        config_or_path: Path object or Config object

    """
    return _get_config_path(config_or_path) / "ca.yaml"


@overload
def get_hosts_config_path(config_or_path: Config) -> Path:
    ...


@overload
def get_hosts_config_path(config_or_path: Path) -> Path:
    ...


def get_hosts_config_path(config_or_path: Path | Config) -> Path:
    """Get the hosts config file path.

    Args:
    ----
        config_or_path: Path object or Config object

    """
    return _get_config_path(config_or_path) / "hosts.yaml"


# Store directory functions


@overload
def get_ca_dir(store_or_path: Store) -> Path:
    ...


@overload
def get_ca_dir(store_or_path: Path) -> Path:
    ...


def get_ca_dir(store_or_path: Path | Store) -> Path:
    """Get the CA directory for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "ca"


@overload
def get_hosts_dir(store_or_path: Store) -> Path:
    ...


@overload
def get_hosts_dir(store_or_path: Path) -> Path:
    ...


def get_hosts_dir(store_or_path: Path | Store) -> Path:
    """Get the hosts directory for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "hosts"


@overload
def get_inventory_path(store_or_path: Store) -> Path:
    ...


@overload
def get_inventory_path(store_or_path: Path) -> Path:
    ...


def get_inventory_path(store_or_path: Path | Store) -> Path:
    """Get the inventory file path.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "inventory.yaml"


@overload
def get_ca_cert_path(store_or_path: Store) -> Path:
    ...


@overload
def get_ca_cert_path(store_or_path: Path) -> Path:
    ...


def get_ca_cert_path(store_or_path: Path | Store) -> Path:
    """Get the CA certificate file path.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_ca_dir(store_or_path) / "ca.crt"


@overload
def get_ca_key_path(store_or_path: Store) -> Path:
    ...


@overload
def get_ca_key_path(store_or_path: Path) -> Path:
    ...


def get_ca_key_path(store_or_path: Path | Store) -> Path:
    """Get the CA key file path.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_ca_dir(store_or_path) / "ca.key.enc"


@overload
def get_ca_crl_path(store_or_path: Store) -> Path:
    ...


@overload
def get_ca_crl_path(store_or_path: Path) -> Path:
    ...


def get_ca_crl_path(store_or_path: Path | Store) -> Path:
    """Get the CA CRL file path.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_ca_dir(store_or_path) / "ca.crl"


@overload
def get_host_dir(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_host_dir(store_or_path: Path, hostname: str) -> Path:
    ...


def get_host_dir(store_or_path: Path | Store, hostname: str) -> Path:
    """Get directory for a specific host.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_hosts_dir(store_or_path) / hostname


@overload
def get_host_cert_path(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_host_cert_path(store_or_path: Path, hostname: str) -> Path:
    ...


def get_host_cert_path(store_or_path: Path | Store, hostname: str) -> Path:
    """Get certificate path for a specific host.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_host_dir(store_or_path, hostname) / "cert.crt"


@overload
def get_host_key_path(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_host_key_path(store_or_path: Path, hostname: str) -> Path:
    ...


def get_host_key_path(store_or_path: Path | Store, hostname: str) -> Path:
    """Get key path for a specific host.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_host_dir(store_or_path, hostname) / "cert.key.enc"


# Store directory functions


@overload
def get_store_ca_dir(store_or_path: Store) -> Path:
    ...


@overload
def get_store_ca_dir(store_or_path: Path) -> Path:
    ...


def get_store_ca_dir(store_or_path: Path | Store) -> Path:
    """Get the CA directory for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "ca"


@overload
def get_store_hosts_dir(store_or_path: Store) -> Path:
    ...


@overload
def get_store_hosts_dir(store_or_path: Path) -> Path:
    ...


def get_store_hosts_dir(store_or_path: Path | Store) -> Path:
    """Get the hosts directory for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "hosts"


@overload
def get_store_inventory_path(store_or_path: Store) -> Path:
    ...


@overload
def get_store_inventory_path(store_or_path: Path) -> Path:
    ...


def get_store_inventory_path(store_or_path: Path | Store) -> Path:
    """Get the inventory file path for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return _get_store_path(store_or_path) / "inventory.yaml"


@overload
def get_store_ca_cert_path(store_or_path: Store) -> Path:
    ...


@overload
def get_store_ca_cert_path(store_or_path: Path) -> Path:
    ...


def get_store_ca_cert_path(store_or_path: Path | Store) -> Path:
    """Get the CA certificate file path for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_store_ca_dir(store_or_path) / "ca.crt"


@overload
def get_store_ca_key_path(store_or_path: Store) -> Path:
    ...


@overload
def get_store_ca_key_path(store_or_path: Path) -> Path:
    ...


def get_store_ca_key_path(store_or_path: Path | Store) -> Path:
    """Get the CA key file path for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_store_ca_dir(store_or_path) / "ca.key.enc"


@overload
def get_store_ca_crl_path(store_or_path: Store) -> Path:
    ...


@overload
def get_store_ca_crl_path(store_or_path: Path) -> Path:
    ...


def get_store_ca_crl_path(store_or_path: Path | Store) -> Path:
    """Get the CA CRL file path for a Store.

    Args:
    ----
        store_or_path: Path object or Store object

    """
    return get_store_ca_dir(store_or_path) / "ca.crl"


@overload
def get_store_host_dir(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_store_host_dir(store_or_path: Path, hostname: str) -> Path:
    ...


def get_store_host_dir(store_or_path: Path | Store, hostname: str) -> Path:
    """Get directory for a specific host in a Store.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_store_hosts_dir(store_or_path) / hostname


@overload
def get_store_host_cert_path(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_store_host_cert_path(store_or_path: Path, hostname: str) -> Path:
    ...


def get_store_host_cert_path(store_or_path: Path | Store, hostname: str) -> Path:
    """Get certificate path for a specific host in a Store.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_store_host_dir(store_or_path, hostname) / "cert.crt"


@overload
def get_store_host_key_path(store_or_path: Store, hostname: str) -> Path:
    ...


@overload
def get_store_host_key_path(store_or_path: Path, hostname: str) -> Path:
    ...


def get_store_host_key_path(store_or_path: Path | Store, hostname: str) -> Path:
    """Get key path for a specific host in a Store.

    Args:
    ----
        store_or_path: Path object or Store object
        hostname: The name of the host

    """
    return get_store_host_dir(store_or_path, hostname) / "cert.key.enc"


@overload
def get_log_path(store_or_path: Store) -> Path:
    ...


@overload
def get_log_path(store_or_path: Path) -> Path:
    ...


def get_log_path(store_or_path: Path | Store) -> Path:
    """Get the log file path in the store.

    Args:
    ----
        store_or_path: Path object or Store object

    Returns:
    -------
        Path to the log file

    """
    return _get_store_path(store_or_path) / "ca.log"
