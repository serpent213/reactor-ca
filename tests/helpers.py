"""Helper functions for ReactorCA tests."""

import os
from pathlib import Path

from reactor_ca.config import create as create_config
from reactor_ca.paths import resolve_paths
from reactor_ca.store import create as create_store
from reactor_ca.models import Config, Store


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
    config_dir = Path(os.path.join(tmpdir, "config"))
    store_dir = Path(os.path.join(tmpdir, "store"))

    config_dir.mkdir(exist_ok=True)
    store_dir.mkdir(exist_ok=True)
    Path(os.path.join(tmpdir, "store", "ca")).mkdir(exist_ok=True, parents=True)
    Path(os.path.join(tmpdir, "store", "hosts")).mkdir(exist_ok=True, parents=True)

    # Create and initialize config and store
    config_result = create_config(config_dir)
    store_result = create_store(store_dir)

    from reactor_ca.result import is_failure

    if is_failure(config_result):
        error_msg = f"Failed to initialize config: {config_result.error}"
        print(error_msg)
        raise RuntimeError(error_msg)

    if is_failure(store_result):
        error_msg = f"Failed to initialize store: {store_result.error}"
        print(error_msg)
        raise RuntimeError(error_msg)

    config = config_result.unwrap()
    store = store_result.unwrap()

    # Print debug information
    print(f"  - Config dir: {config_dir} (exists={config_dir.exists()})")
    print(f"  - Store dir: {store_dir} (exists={store_dir.exists()})")
    print(f"  - CA dir: {store_dir / 'ca'} (exists={(store_dir / 'ca').exists()})")
    print(f"  - Hosts dir: {store_dir / 'hosts'} (exists={(store_dir / 'hosts').exists()})")

    return store


def assert_cert_paths(store: Store, hostname: str = None) -> None:
    """Assert that certificate paths exist for CA or a specific host.

    Args:
    ----
        store: Store instance to use for path resolution
        hostname: Optional hostname to check certificate paths for

    """
    from reactor_ca.paths import (
        get_store_ca_cert_path,
        get_store_ca_key_path,
        get_store_host_cert_path,
        get_store_host_key_path,
    )

    if hostname:
        # Host certificate paths
        cert_path = get_store_host_cert_path(store, hostname)
        key_path = get_store_host_key_path(store, hostname)
        assert cert_path.exists(), f"Host certificate not found at {cert_path}"
        assert key_path.exists(), f"Host key not found at {key_path}"
    else:
        # CA certificate paths
        ca_cert_path = get_store_ca_cert_path(store)
        ca_key_path = get_store_ca_key_path(store)
        assert ca_cert_path.exists(), f"CA certificate not found at {ca_cert_path}"
        assert ca_key_path.exists(), f"CA key not found at {ca_key_path}"
