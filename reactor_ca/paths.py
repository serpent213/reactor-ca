"""Central path definitions for ReactorCA."""

from pathlib import Path

# Environment variable names
ENV_ROOT_DIR = "REACTOR_CA_ROOT"
ENV_CONFIG_DIR = "REACTOR_CA_CONFIG_DIR"
ENV_STORE_DIR = "REACTOR_CA_STORE_DIR"

# Schema directory is always relative to the code, not user configuration
SCHEMAS_DIR = Path(__file__).parent / "schemas"
