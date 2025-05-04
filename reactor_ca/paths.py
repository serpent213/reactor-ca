"""Path management for ReactorCA."""

import os
from pathlib import Path

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


def get_ca_config_path(config_dir: Path) -> Path:
    """Get the CA config file path."""
    return config_dir / "ca.yaml"


def get_hosts_config_path(config_dir: Path) -> Path:
    """Get the hosts config file path."""
    return config_dir / "hosts.yaml"


def ensure_dirs(config_dir: Path, store_dir: Path) -> None:
    """Create all necessary directories.

    Args:
    ----
        config_dir: Path to configuration directory
        store_dir: Path to store directory

    """
    config_dir.mkdir(parents=True, exist_ok=True)
    store_dir.mkdir(parents=True, exist_ok=True)
    get_ca_dir(store_dir).mkdir(parents=True, exist_ok=True)
    get_hosts_dir(store_dir).mkdir(parents=True, exist_ok=True)


# Store


def get_ca_dir(store_dir: Path) -> Path:
    """Get the CA directory."""
    return store_dir / "ca"


def get_hosts_dir(store_dir: Path) -> Path:
    """Get the hosts directory."""
    return store_dir / "hosts"


def get_inventory_path(store_dir: Path) -> Path:
    """Get the inventory file path."""
    return store_dir / "inventory.yaml"


def get_ca_cert_path(store_dir: Path) -> Path:
    """Get the CA certificate file path."""
    return get_ca_dir(store_dir) / "ca.crt"


def get_ca_key_path(store_dir: Path) -> Path:
    """Get the CA key file path."""
    return get_ca_dir(store_dir) / "ca.key.enc"


def get_ca_crl_path(store_dir: Path) -> Path:
    """Get the CA CRL file path."""
    return get_ca_dir(store_dir) / "ca.crl"


def get_host_dir(store_dir: Path, hostname: str) -> Path:
    """Get directory for a specific host."""
    return get_hosts_dir(store_dir) / hostname


def get_host_cert_path(store_dir: Path, hostname: str) -> Path:
    """Get certificate path for a specific host."""
    return get_host_dir(store_dir, hostname) / "cert.crt"


def get_host_key_path(store_dir: Path, hostname: str) -> Path:
    """Get key path for a specific host."""
    return get_host_dir(store_dir, hostname) / "cert.key.enc"
