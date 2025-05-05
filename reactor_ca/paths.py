"""Path management for ReactorCA."""

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reactor_ca.models import Config

# Environment variable names
ENV_ROOT_DIR = "REACTOR_CA_ROOT"
ENV_CONFIG_DIR = "REACTOR_CA_CONFIG_DIR"
ENV_STORE_DIR = "REACTOR_CA_STORE_DIR"

# Schema directory is always relative to the code, not user configuration
SCHEMAS_DIR = Path(__file__).parent / "schemas"


def resolve_paths(
    config_dir: str | None = None, store_dir: str | None = None, root_dir: str | None = None
) -> tuple[Path, Path]:
    """Resolve configuration and store paths.

    The resolution order is:
    1. Explicitly provided arguments
    2. Environment variables
    3. Default values (current directory with standard subdirectories)

    Args:
    ----
        config_dir: Optional path to configuration directory
        store_dir: Optional path to store directory
        root_dir: Optional root directory (used if config_dir or store_dir not provided)

    Returns:
    -------
        Tuple of (config_dir, store_dir) as Path objects

    """
    # Resolve root directory
    root = Path(root_dir) if root_dir else Path(os.environ.get(ENV_ROOT_DIR, "."))

    # Resolve config and store directories
    config = Path(config_dir) if config_dir else Path(os.environ.get(ENV_CONFIG_DIR, root / "config"))
    store = Path(store_dir) if store_dir else Path(os.environ.get(ENV_STORE_DIR, root / "store"))

    return config, store


# Config

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reactor_ca.models import Config


def get_ca_config_path(config: 'Config') -> Path:
    """Get the CA config file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return Path(config.config_path) / "ca.yaml"


def get_hosts_config_path(config: 'Config') -> Path:
    """Get the hosts config file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return Path(config.config_path) / "hosts.yaml"


def ensure_dirs(config: 'Config') -> None:
    """Create all necessary directories.

    Args:
    ----
        config: Config object containing path information
    """
    config_dir = Path(config.config_path)
    store_dir = Path(config.store_path)
    
    config_dir.mkdir(parents=True, exist_ok=True)
    store_dir.mkdir(parents=True, exist_ok=True)
    get_ca_dir(config).mkdir(parents=True, exist_ok=True)
    get_hosts_dir(config).mkdir(parents=True, exist_ok=True)


# Store


def get_ca_dir(config: 'Config') -> Path:
    """Get the CA directory.
    
    Args:
    ----
        config: Config object containing path information
    """
    return Path(config.store_path) / "ca"


def get_hosts_dir(config: 'Config') -> Path:
    """Get the hosts directory.
    
    Args:
    ----
        config: Config object containing path information
    """
    return Path(config.store_path) / "hosts"


def get_inventory_path(config: 'Config') -> Path:
    """Get the inventory file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return Path(config.store_path) / "inventory.yaml"


def get_ca_cert_path(config: 'Config') -> Path:
    """Get the CA certificate file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return get_ca_dir(config) / "ca.crt"


def get_ca_key_path(config: 'Config') -> Path:
    """Get the CA key file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return get_ca_dir(config) / "ca.key.enc"


def get_ca_crl_path(config: 'Config') -> Path:
    """Get the CA CRL file path.
    
    Args:
    ----
        config: Config object containing path information
    """
    return get_ca_dir(config) / "ca.crl"


def get_host_dir(config: 'Config', hostname: str) -> Path:
    """Get directory for a specific host.
    
    Args:
    ----
        config: Config object containing path information
        hostname: The name of the host
    """
    return get_hosts_dir(config) / hostname


def get_host_cert_path(config: 'Config', hostname: str) -> Path:
    """Get certificate path for a specific host.
    
    Args:
    ----
        config: Config object containing path information
        hostname: The name of the host
    """
    return get_host_dir(config, hostname) / "cert.crt"


def get_host_key_path(config: 'Config', hostname: str) -> Path:
    """Get key path for a specific host.
    
    Args:
    ----
        config: Config object containing path information
        hostname: The name of the host
    """
    return get_host_dir(config, hostname) / "cert.key.enc"
