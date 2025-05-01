"""Helper functions for ReactorCA tests."""

import os
from pathlib import Path

from reactor_ca.config import Config
from reactor_ca.store import Store


def setup_test_env(tmpdir: str) -> Store:
    """Set up a test environment with proper configuration.

    This ensures that all environment variables are set correctly
    and returns a properly configured Store instance pointing to
    the temporary directory.

    Args:
    ----
        tmpdir: Path to temporary directory

    Returns:
    -------
        Store instance configured for the test environment

    """
    # Clear existing environment variables that might interfere
    for var in ["REACTOR_CA_ROOT", "REACTOR_CA_CONFIG_DIR", "REACTOR_CA_STORE_DIR"]:
        if var in os.environ:
            del os.environ[var]

    # Set up environment variables for the test
    os.environ["REACTOR_CA_ROOT"] = str(tmpdir)

    # Create required directories
    Path(os.path.join(tmpdir, "config")).mkdir(exist_ok=True)
    Path(os.path.join(tmpdir, "store")).mkdir(exist_ok=True)
    Path(os.path.join(tmpdir, "store", "ca")).mkdir(exist_ok=True, parents=True)
    Path(os.path.join(tmpdir, "store", "hosts")).mkdir(exist_ok=True, parents=True)

    # Create config with absolute paths
    config = Config.create(root_dir=str(tmpdir))

    # Create and initialize store
    store = Store(config)
    store.init()

    # Print debug information
    print(f"  - Config dir: {store.config.config_dir} (exists={store.config.config_dir.exists()})")
    print(f"  - Store dir: {store.config.store_dir} (exists={store.config.store_dir.exists()})")
    print(f"  - CA dir: {store.config.ca_dir} (exists={store.config.ca_dir.exists()})")
    print(f"  - Hosts dir: {store.config.hosts_dir} (exists={store.config.hosts_dir.exists()})")

    return store


def assert_cert_paths(store: Store, hostname: str = None) -> None:
    """Assert that certificate paths exist for CA or a specific host.

    Args:
    ----
        store: Store instance to use for path resolution
        hostname: Optional hostname to check certificate paths for

    """
    if hostname:
        # Host certificate paths
        cert_path = store.get_host_cert_path(hostname)
        key_path = store.get_host_key_path(hostname)
        assert cert_path.exists(), f"Host certificate not found at {cert_path}"
        assert key_path.exists(), f"Host key not found at {key_path}"
    else:
        # CA certificate paths
        ca_cert_path = store.get_ca_cert_path()
        ca_key_path = store.get_ca_key_path()
        assert ca_cert_path.exists(), f"CA certificate not found at {ca_cert_path}"
        assert ca_key_path.exists(), f"CA key not found at {ca_key_path}"
