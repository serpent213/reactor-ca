# Refactoring Config to a Functional Approach

## Current State Analysis

The current configuration system is centered around the `Config` class in `config.py`, which:

1. Manages application paths through properties and methods
2. Loads and validates YAML configuration files through associated functions
3. Converts raw config data to typed dataclasses in `models.py`
4. Contains a variety of validation functions at different levels

Current operations use Config through Store:
```python
def issue_ca(store: Store | None = None) -> None:
    # Store wraps Config
    ca_config_path = store.config.ca_config_path
    ca_config = load_ca_config(ca_config_path)
    # ...
```

## Issues with Current Approach

1. The `Config` class combines path resolution and configuration management
2. Multiple validation functions with overlapping responsibilities 
   (`validate_config`, `validate_configs`, `validate_config_before_operation`, `validate_config_files`)
3. Configuration is read on-demand in multiple places, causing duplication
4. Two `Config` classes (one in `models.py` and another in `config.py`)
5. Mixture of class-based and functional approaches
6. Tightly coupled with `Store` class

## Proposed Functional Approach

We can refactor to a purely functional approach that loads configuration on demand while maintaining the existing dataclasses in `models.py`.

### 1. Path Management Functions

```python
"""Path management for ReactorCA."""

import os
from pathlib import Path

# Environment variable names
ENV_CONFIG_DIR = "REACTOR_CA_CONFIG_DIR"
ENV_STORE_DIR = "REACTOR_CA_STORE_DIR"
ENV_ROOT_DIR = "REACTOR_CA_ROOT_DIR"

# Current directory for schema files
SCHEMAS_DIR = Path(__file__).parent / "schemas"

def resolve_paths(
    config_dir: str | None = None, 
    store_dir: str | None = None, 
    root_dir: str | None = None
) -> tuple[Path, Path]:
    """Resolve configuration and store paths.
    
    Resolution order:
    1. Explicitly provided arguments
    2. Environment variables
    3. Default values (current directory with standard subdirectories)
    """
    # Resolve root directory
    root = Path(root_dir) if root_dir else Path(os.environ.get(ENV_ROOT_DIR, "."))
    
    # Resolve config and store directories
    config = Path(config_dir) if config_dir else Path(os.environ.get(ENV_CONFIG_DIR, root / "config"))
    store = Path(store_dir) if store_dir else Path(os.environ.get(ENV_STORE_DIR, root / "store"))
    
    return config, store

def get_ca_dir(store_dir: Path) -> Path:
    """Get the CA directory."""
    return store_dir / "ca"

def get_hosts_dir(store_dir: Path) -> Path:
    """Get the hosts directory."""
    return store_dir / "hosts"

def get_ca_config_path(config_dir: Path) -> Path:
    """Get the CA config file path."""
    return config_dir / "ca.yaml"

def get_hosts_config_path(config_dir: Path) -> Path:
    """Get the hosts config file path."""
    return config_dir / "hosts.yaml"

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

def ensure_dirs(config_dir: Path, store_dir: Path) -> None:
    """Create all necessary directories."""
    config_dir.mkdir(parents=True, exist_ok=True)
    store_dir.mkdir(parents=True, exist_ok=True)
    get_ca_dir(store_dir).mkdir(parents=True, exist_ok=True)
    get_hosts_dir(store_dir).mkdir(parents=True, exist_ok=True)
```

### 2. Configuration Operations Functions

```python
"""Configuration operations for ReactorCA."""

from pathlib import Path
from typing import Any, cast

import yamale
import yaml
from rich.console import Console

from reactor_ca.models import (
    AlternativeNames, CAConfig, HostConfig, PasswordConfig,
    SubjectIdentity, ValidityConfig
)
from reactor_ca.paths import (
    SCHEMAS_DIR, get_ca_config_path, get_hosts_config_path
)

CONSOLE = Console()

# Exception classes
class ConfigError(Exception):
    """Base exception for configuration errors."""
    pass

class ConfigNotFoundError(ConfigError):
    """Exception raised when a configuration file is not found."""
    pass

class ConfigValidationError(ConfigError):
    """Exception raised when a configuration file is invalid."""
    pass

def validate_yaml(file_path: Path, schema_name: str) -> tuple[bool, list[str]]:
    """Validate a YAML file against a schema."""
    if not file_path.exists():
        return False, [f"File not found: {file_path}"]

    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.exists():
        return False, [f"Schema file not found: {schema_path}"]

    schema = yamale.make_schema(schema_path)
    data = yamale.make_data(file_path)

    try:
        yamale.validate(schema, data)
        return True, []
    except ValueError as e:
        return False, [str(error) for error in e.args[0]]

def load_yaml(file_path: Path) -> dict[str, Any]:
    """Load YAML file into a dictionary."""
    if not file_path.exists():
        raise ConfigNotFoundError(f"File not found: {file_path}")

    with open(file_path, encoding="locale") as f:
        return yaml.safe_load(f) or {}

def save_yaml(data: dict[str, Any], file_path: Path) -> None:
    """Save dictionary to a YAML file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, "w", encoding="locale") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

def load_ca_config(config_dir: Path) -> CAConfig:
    """Load CA configuration from YAML into a CAConfig object."""
    ca_config_path = get_ca_config_path(config_dir)
    
    # Validate against schema
    valid, errors = validate_yaml(ca_config_path, "ca_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid CA configuration:\n{error_message}")
    
    # Load data
    config_dict = load_yaml(ca_config_path)
    ca_dict = config_dict.get("ca", config_dict)  # Handle both nested and flat formats
    
    # Extract configuration components
    validity_data = ca_dict.get("validity") or {}
    validity_days = ca_dict.get("validity_days")
    
    # Process validity configuration
    if isinstance(validity_data, dict):
        validity = ValidityConfig(
            days=validity_data.get("days"), 
            years=validity_data.get("years")
        )
    else:
        validity = ValidityConfig(days=validity_days or validity_data)
    
    # Process password configuration
    password_config = ca_dict.get("password", {})
    password = PasswordConfig(
        min_length=password_config.get("min_length", 12),
        file=password_config.get("file", ""),
        env_var=password_config.get("env_var", "REACTOR_CA_PASSWORD"),
    )
    
    # Create and return CAConfig
    try:
        return CAConfig(
            common_name=ca_dict["common_name"],
            organization=ca_dict["organization"],
            organization_unit=ca_dict.get("organization_unit", ""),
            country=ca_dict["country"],
            state=ca_dict["state"],
            locality=ca_dict["locality"],
            email=ca_dict["email"],
            key_algorithm=ca_dict.get("key_algorithm", "RSA2048"),
            validity=validity,
            password=password,
            hash_algorithm=ca_dict.get("hash_algorithm", "SHA256"),
        )
    except KeyError as e:
        CONSOLE.print(f"[bold red]Error:[/bold red] Missing required field in configuration: {e}")
        raise ConfigValidationError(f"Missing required field in configuration: {e}") from e

def load_hosts_config(config_dir: Path) -> dict[str, HostConfig]:
    """Load hosts configuration from YAML into a dictionary of HostConfig objects."""
    hosts_config_path = get_hosts_config_path(config_dir)
    
    # Validate against schema
    valid, errors = validate_yaml(hosts_config_path, "hosts_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid hosts configuration:\n{error_message}")
    
    # Load data
    hosts_dict: dict[str, HostConfig] = {}
    config_dict = load_yaml(hosts_config_path)
    hosts_data = config_dict.get("hosts", {})
    
    # Convert list of host dicts to a dict keyed by name if needed
    if isinstance(hosts_data, list):
        hosts_map: dict[str, Any] = {}
        for host in hosts_data:
            if "name" in host:
                hosts_map[host["name"]] = host.copy()
            else:
                CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Host entry missing 'name' field: {host}")
        hosts_data = hosts_map
    
    # Process each host configuration
    for host_name, host_data in hosts_data.items():
        hosts_dict[host_name] = _parse_host_config(host_name, host_data)
    
    return hosts_dict

def get_host_config(config_dir: Path, host_name: str) -> HostConfig:
    """Get configuration for a specific host."""
    hosts_dict = load_hosts_config(config_dir)
    
    if host_name not in hosts_dict:
        raise ValueError(f"Host not found in configuration: {host_name}")
    
    return hosts_dict[host_name]

# Helper functions for parsing host configurations remain mostly the same
def _parse_host_config(host_name: str, host_data: dict[str, Any]) -> HostConfig:
    """Parse host configuration data into a HostConfig object."""
    # These helper functions would remain with the existing implementation
    # ...

# Default configuration factories and init functions
def get_default_ca_config() -> dict[str, Any]:
    """Return a default CA configuration dictionary."""
    # Implementation unchanged from current code
    # ...

def get_default_hosts_config() -> dict[str, Any]:
    """Return a default hosts configuration dictionary."""
    # Implementation unchanged from current code
    # ...

def create_default_config(config_dir: Path, store_dir: Path) -> None:
    """Create default configuration files."""
    from reactor_ca.paths import ensure_dirs
    
    # Ensure directories exist
    ensure_dirs(config_dir, store_dir)
    
    # Get default configurations
    ca_config = get_default_ca_config()
    hosts_config = get_default_hosts_config()
    
    # Write configuration files
    ca_config_path = get_ca_config_path(config_dir)
    hosts_config_path = get_hosts_config_path(config_dir)
    
    write_config_file(ca_config, ca_config_path, "ca")
    write_config_file(hosts_config, hosts_config_path, "hosts")
    
    CONSOLE.print("✅ Created default configuration files:")
    CONSOLE.print(f"   CA config: [bold]{ca_config_path}[/bold]")
    CONSOLE.print(f"   Hosts config: [bold]{hosts_config_path}[/bold]")
    CONSOLE.print("Please review and customize these files before initializing the CA.")
```

### 3. Update Store Class to Use Functional Approach

```python
"""Certificate store operations for ReactorCA."""

from pathlib import Path

from reactor_ca.paths import (
    resolve_paths, get_ca_dir, get_hosts_dir,
    get_ca_cert_path, get_ca_key_path, 
    get_host_cert_path, get_host_key_path
)
from reactor_ca.config import (
    load_ca_config, load_hosts_config
)

class Store:
    """Certificate store management."""
    
    def __init__(
        self,
        config_dir: Path | None = None,
        store_dir: Path | None = None,
        root_dir: Path | None = None
    ) -> None:
        """Initialize store with resolved paths."""
        self.config_dir, self.store_dir = resolve_paths(
            config_dir=str(config_dir) if config_dir else None,
            store_dir=str(store_dir) if store_dir else None,
            root_dir=str(root_dir) if root_dir else None
        )
        self._password: str | None = None
    
    def get_ca_cert_path(self) -> Path:
        """Get the CA certificate path."""
        return get_ca_cert_path(self.store_dir)
    
    def get_ca_key_path(self) -> Path:
        """Get the CA key path."""
        return get_ca_key_path(self.store_dir)
    
    def get_host_cert_path(self, hostname: str) -> Path:
        """Get the certificate path for a host."""
        return get_host_cert_path(self.store_dir, hostname)
    
    # Additional methods using the functional path helpers
    # ...
    
    def load_ca_config(self) -> CAConfig:
        """Load the CA configuration."""
        return load_ca_config(self.config_dir)
    
    def load_hosts_config(self) -> dict[str, HostConfig]:
        """Load the hosts configuration."""
        return load_hosts_config(self.config_dir)
    
    def get_host_config(self, hostname: str) -> HostConfig:
        """Get configuration for a specific host."""
        return get_host_config(self.config_dir, hostname)
    
    # Rest of Store methods remain largely unchanged
    # ...
```

### 4. Update Operational Code

```python
def issue_ca(store: Store | None = None) -> None:
    """Issue a CA certificate."""
    # If store is not provided, create a default one
    if store is None:
        store = Store()
    
    # Load CA configuration
    try:
        ca_config = store.load_ca_config()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load CA configuration: {e}")
        return
    
    # Rest of implementation uses ca_config directly
    # ...
```

## Benefits of the New Approach

1. **Clean separation of concerns**:
   - `paths.py`: Path resolution and management
   - `config.py`: Configuration loading, validation, and parsing
   - Operational code: Business logic using configurations

2. **On-demand loading**:
   - Configuration is loaded only when needed
   - No global state or class encapsulation
   - Each function has a clear scope and purpose

3. **Simplified validation**:
   - Single validation function `validate_yaml` replaces multiple overlapping ones
   - Each config loading function validates its own input

4. **Better testability**:
   - Pure functions are easier to test
   - Explicit dependencies and inputs
   - No hidden state or side effects

5. **Remove duplication**:
   - Path resolution logic in one place
   - Common validation in one place
   - Configuration parsing in specialized functions

6. **Backward compatibility**:
   - `Store` class can be updated to use the new functions
   - Existing dataclasses in `models.py` are preserved
   - Only `Config` class is removed and replaced with functions

## Migration Path

1. Create `paths.py` with path resolution functions
2. Modify `config.py` to use a functional approach
3. Update `Store` class to use the new functions
4. Adjust operational code to work with the new approach
5. Remove the `Config` class from both files
6. Update documentation and tests