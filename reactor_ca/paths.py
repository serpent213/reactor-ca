"""Central path definitions for ReactorCA."""

from pathlib import Path

# Define central directory paths
ROOT_DIR = Path(".")
CONFIG_DIR = ROOT_DIR / "config"
STORE_DIR = ROOT_DIR / "store"
CA_DIR = STORE_DIR / "ca"
HOSTS_DIR = STORE_DIR / "hosts"
