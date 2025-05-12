"""Configuration operations for ReactorCA."""

from pathlib import Path
from typing import Any, Dict, Optional, cast

import json
from pydantic import ValidationError
from rich.console import Console
from ruamel.yaml import YAML

from reactor_ca.defaults import (
    DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_HOST_VALIDITY_DAYS,
    get_default_ca_config,
    get_default_hosts_config,
)
from reactor_ca.models import (
    AlternativeNames,
    CAConfig,
    Config,
    DeploymentConfig,
    ExportConfig,
    HostConfig,
    PasswordConfig,
    ValidityConfig,
)
from reactor_ca.paths import (
    get_ca_config_path,
    get_hosts_config_path,
)
from reactor_ca.result import Failure, Result, Success

CONSOLE = Console()
yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


def create(config_path: Path) -> Result[Config, str]:
    """Create configuration files and directories with default values.

    Returns a Config object if successful.

    Args:
    ----
        config_path: Path to config directory

    Returns:
    -------
        Result with Config object or error message

    """
    # Determine store path, use sibling 'store' directory by default
    store_path = config_path.parent / "store"

    # Create directories
    config_path.mkdir(parents=True, exist_ok=True)
    store_path.mkdir(parents=True, exist_ok=True)

    # Get default configurations
    ca_config_data = get_default_ca_config()
    hosts_config_data = get_default_hosts_config()

    # Write CA config file
    ca_config_file_path = get_ca_config_path(config_path)
    if not ca_config_file_path.exists():
        ca_result = _write_config_file(ca_config_data, ca_config_file_path, "ca")
        if isinstance(ca_result, Failure):
            return Failure(f"Failed to create CA config: {ca_result.error}")
        CONSOLE.print(f"Created CA config at {ca_config_file_path}")
    else:
        CONSOLE.print(f"CA config already exists at {ca_config_file_path}, not overwriting")

    # Write hosts config file
    hosts_config_file_path = get_hosts_config_path(config_path)
    if not hosts_config_file_path.exists():
        hosts_result = _write_config_file(hosts_config_data, hosts_config_file_path, "hosts")
        if isinstance(hosts_result, Failure):
            return Failure(f"Failed to create hosts config: {hosts_result.error}")
        CONSOLE.print(f"Created hosts config at {hosts_config_file_path}")
    else:
        CONSOLE.print(f"Hosts config already exists at {hosts_config_file_path}, not overwriting")

    # Now initialize and return the config
    return init(config_path)


def init(config_path: Path) -> Result[Config, str]:
    """Initialize a Config object from existing configuration files.

    Args:
    ----
        config_path: Path to config directory

    Returns:
    -------
        Result with Config object or error message

    """
    # Determine store path, use sibling 'store' directory by default
    config_path.parent / "store"

    if not config_path.exists():
        return Failure(f"Config directory does not exist: {config_path}")

    # Load CA config
    ca_config_result = _load_ca_config(config_path)
    if isinstance(ca_config_result, Failure):
        return Failure(f"Failed to load CA config: {ca_config_result.error}")

    # Load hosts config
    hosts_config_result = _load_hosts_config(config_path)
    if isinstance(hosts_config_result, Failure):
        return Failure(f"Failed to load hosts config: {hosts_config_result.error}")

    # Create and return Config object
    ca_config = ca_config_result.value
    hosts_config = hosts_config_result.value

    return Success(
        Config(
            config_path=config_path,
            ca_config=ca_config,
            hosts_config=hosts_config,
        )
    )


def validate(config_path: Path) -> Result[bool, str]:
    """Validate configuration files.

    Args:
    ----
        config_path: Path to the configuration directory

    Returns:
    -------
        Result with True if all configurations are valid, or error message

    """
    ca_config_path = get_ca_config_path(config_path)
    hosts_config_path = get_hosts_config_path(config_path)

    # Check if CA config exists (required)
    if not ca_config_path.exists():
        CONSOLE.print(f"[bold red]Error:[/bold red] CA configuration file not found: {ca_config_path}")
        CONSOLE.print("Run 'ca config init' to create a default configuration.")
        return Failure("CA configuration file not found")

    # Hosts config is optional
    if not hosts_config_path.exists():
        CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {hosts_config_path}")
        CONSOLE.print("You may want to create a hosts configuration to issue certificates.")

    # Validate CA config
    ca_validation = _validate_yaml(ca_config_path, "ca")
    if isinstance(ca_validation, Failure):
        CONSOLE.print("[bold red]CA configuration validation failed:[/bold red]")
        for error in ca_validation.error:
            CONSOLE.print(f"  - {error}")
        return Failure("CA configuration validation failed")

    CONSOLE.print("✅ CA configuration is valid")

    # Validate hosts config if it exists
    if hosts_config_path.exists():
        hosts_validation = _validate_yaml(hosts_config_path, "hosts")
        if isinstance(hosts_validation, Failure):
            CONSOLE.print("[bold red]Hosts configuration validation failed:[/bold red]")
            for error in hosts_validation.error:
                CONSOLE.print(f"  - {error}")
            return Failure("Hosts configuration validation failed")

        CONSOLE.print("✅ Hosts configuration is valid")

    return Success(True)


def save_ca_config(config: Config) -> Result[None, str]:
    """Save CA configuration to file.

    Args:
    ----
        config: Config object containing CA config

    Returns:
    -------
        Result with None for success or error message for failure

    """
    if config.ca_config is None:
        return Failure("No CA configuration to save")

    try:
        # Use Pydantic's model_dump to convert CAConfig to dictionary
        ca_dict = config.ca_config.model_dump(exclude_none=True, exclude_unset=True)
        
        # Format validity days/years correctly
        if "validity" in ca_dict and "days" in ca_dict["validity"]:
            days_result = config.ca_config.validity.to_days()
            if isinstance(days_result, Success):
                ca_dict["validity"] = {"days": days_result.unwrap()}
        
        # Wrap in 'ca' key for config file format
        config_dict = {"ca": ca_dict}

        # Write config to file
        ca_config_path = get_ca_config_path(config.config_path)
        return _write_config_file(config_dict, ca_config_path, "ca")
    except Exception as e:
        return Failure(f"Error saving CA configuration: {str(e)}")


def save_hosts_config(config: Config) -> Result[None, str]:
    """Save hosts configuration to file.

    Args:
    ----
        config: Config object containing hosts config

    Returns:
    -------
        Result with None for success or error message for failure

    """
    if not config.hosts_config:
        return Failure("No hosts configuration to save")

    try:
        # Convert HostConfig objects to dictionary
        hosts_data = {}
        for host_id, host_config in config.hosts_config.items():
            host_data = _host_config_to_dict(host_config)
            hosts_data[host_id] = host_data

        # Write hosts config to file
        hosts_config_path = get_hosts_config_path(config.config_path)
        return _write_config_file({"hosts": hosts_data}, hosts_config_path, "hosts")
    except Exception as e:
        return Failure(f"Error saving hosts configuration: {str(e)}")


def save(config: Config) -> Result[None, str]:
    """Save all configuration to files.

    Args:
    ----
        config: Config object containing configuration to save

    Returns:
    -------
        Result with None for success or error message for failure

    """
    # Save CA config
    ca_result = save_ca_config(config)
    if isinstance(ca_result, Failure):
        return ca_result

    # Save hosts config
    hosts_result = save_hosts_config(config)
    if isinstance(hosts_result, Failure):
        return hosts_result

    return Success(None)


def get_host_config(config: Config, host_id: str) -> Result[HostConfig, str]:
    """Get the configuration for a specific host.

    Args:
    ----
        config: Config object
        host_id: ID of the host to get configuration for

    Returns:
    -------
        Result with HostConfig object for the specified host or error message

    """
    if not config.hosts_config:
        return Failure("No hosts configuration available")

    if host_id not in config.hosts_config:
        return Failure(f"Host not found in configuration: {host_id}")

    return Success(config.hosts_config[host_id])


def _validate_yaml(file_path: Path, config_type: str) -> Result[None, list[str]]:
    """Validate a YAML file using Pydantic models.

    Args:
    ----
        file_path: Path to the configuration file
        config_type: Type of configuration ('ca' or 'hosts')

    Returns:
    -------
        Result with None for success or list of error messages for failure

    """
    if not file_path.exists():
        return Failure([f"Configuration file not found: {file_path}"])

    try:
        # Load the YAML file
        with open(file_path, encoding="locale") as f:
            config_dict = yaml.load(f) or {}
        
        # Validate based on config type
        if config_type == 'ca':
            ca_data = config_dict.get('ca', {})
            # Validate using CAConfig Pydantic model
            CAConfig.model_validate(ca_data)
        elif config_type == 'hosts':
            hosts_data = config_dict.get('hosts', {})
            
            # If hosts is a list, convert to dict for validation
            if isinstance(hosts_data, list):
                hosts_dict = {}
                for host in hosts_data:
                    if 'host_id' in host:
                        hosts_dict[host['host_id']] = host
                    else:
                        return Failure([f"Host missing required 'host_id' field: {host}"])
                hosts_data = hosts_dict
            
            # Validate each host configuration
            for host_id, host_data in hosts_data.items():
                # Ensure host_id is included in the data for validation
                host_data_with_id = {**host_data, 'host_id': host_id}
                HostConfig.model_validate(host_data_with_id)
        else:
            return Failure([f"Unknown configuration type: {config_type}"])
        
        return Success(None)
    except ValidationError as e:
        # Extract error messages from Pydantic ValidationError
        return Failure([f"{'.'.join(str(loc) for loc in error['loc'])}: {error['msg']}" for error in json.loads(e.json())])
    except Exception as e:
        return Failure([f"Error validating configuration: {str(e)}"])


def _load_ca_config(config_path: Path) -> Result[CAConfig, str]:
    """Load and validate CA configuration into a CAConfig object.

    Args:
    ----
        config_path: Path to the configuration directory

    Returns:
    -------
        Result with CAConfig object or error message

    """
    ca_config_path = get_ca_config_path(config_path)

    # Validate first
    validation_result = _validate_yaml(ca_config_path, "ca")
    if isinstance(validation_result, Failure):
        error_message = "\n".join(validation_result.error)
        return Failure(f"Invalid CA configuration:\n{error_message}")

    # Load the configuration
    try:
        with open(ca_config_path, encoding="locale") as f:
            config_dict = yaml.load(f) or {}
    except Exception as e:
        return Failure(f"Error loading CA configuration file: {str(e)}")

    # Check if config is in the expected format (may be nested under 'ca' key)
    if "ca" in config_dict:
        config_dict = config_dict["ca"]

    try:
        # Use Pydantic's model_validate to convert the dictionary to a CAConfig object
        ca_config = CAConfig.model_validate(config_dict)
        return Success(ca_config)
    except ValidationError as e:
        # Parse validation errors to provide meaningful error messages
        errors = json.loads(e.json())
        error_message = "\n".join([f"{'.'.join(str(loc) for loc in error['loc'])}: {error['msg']}" for error in errors])
        CONSOLE.print(f"[bold red]Error:[/bold red] Invalid CA configuration: {error_message}")
        return Failure(f"Invalid CA configuration: {error_message}")
    except Exception as e:
        return Failure(f"Error processing CA configuration: {str(e)}")


def _load_hosts_config(config_path: Path) -> Result[dict[str, HostConfig], str]:
    """Load and validate hosts configuration into a dictionary of HostConfig objects.

    Args:
    ----
        config_path: Path to the configuration directory

    Returns:
    -------
        Result with dictionary mapping host names to HostConfig objects or error message

    """
    hosts_config_path = get_hosts_config_path(config_path)

    # Check if hosts config exists
    if not hosts_config_path.exists():
        return Success({})  # Return empty dict if no hosts config

    # Validate first
    validation_result = _validate_yaml(hosts_config_path, "hosts")
    if isinstance(validation_result, Failure):
        error_message = "\n".join(validation_result.error)
        return Failure(f"Invalid hosts configuration:\n{error_message}")

    # Load the configuration
    try:
        with open(hosts_config_path, encoding="locale") as f:
            config_dict = yaml.load(f) or {}
    except Exception as e:
        return Failure(f"Error loading hosts configuration file: {str(e)}")

    hosts_dict: Dict[str, HostConfig] = {}
    hosts_data = config_dict.get("hosts", {})

    # Convert a list of host dicts to a dict keyed by host_id
    if isinstance(hosts_data, list):
        hosts_map = {}
        for host in hosts_data:
            if "host_id" in host:
                hosts_map[host["host_id"]] = host.copy()
            else:
                CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Host entry missing 'host_id' field: {host}")
        hosts_data = hosts_map

    try:
        for host_id, host_data in hosts_data.items():
            try:
                # Ensure host_id is included in the data
                host_data_with_id = {**host_data, "host_id": host_id}
                # Use Pydantic's model_validate to convert to HostConfig
                host_config = HostConfig.model_validate(host_data_with_id)
                hosts_dict[host_id] = host_config
            except ValidationError as e:
                errors = json.loads(e.json())
                error_message = "\n".join([f"{'.'.join(str(loc) for loc in error['loc'])}: {error['msg']}" for error in errors])
                return Failure(f"Error parsing host {host_id}: {error_message}")

        return Success(hosts_dict)
    except Exception as e:
        CONSOLE.print(f"[bold red]Error processing hosts config:[/bold red] {e}")
        return Failure(f"Failed to process hosts configuration: {e}")


def _write_config_file(config: dict, config_path: Path, config_type: str = "ca") -> Result[None, str]:
    """Write configuration to file with standard header.

    Args:
    ----
        config: Configuration dictionary to write
        config_path: Path to save the configuration file
        config_type: Type of configuration ("ca" or "hosts")

    Returns:
    -------
        Result with None for success or error message for failure

    """
    try:
        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Select appropriate header based on config type
        headers = {
            "ca": [
                "# ReactorCA Configuration",
                "# This file contains settings for the Certificate Authority",
                "# It is safe to modify this file directly\n",
            ],
            "hosts": [
                "# ReactorCA Hosts Configuration",
                "# This file contains settings for host certificates",
                "# It is safe to modify this file directly\n",
            ],
        }

        header = headers.get(config_type, headers["ca"])

        # Write file with headers and content
        with open(config_path, "w", encoding="locale") as f:
            # Write header comments
            for line in header:
                f.write(line + "\n")

            # Write YAML content
            yaml.dump(config, f)

        return Success(None)
    except Exception as e:
        return Failure(f"Error writing configuration file: {str(e)}")


# We'll remove this function since Pydantic handles validation directly


def _host_config_to_dict(host_config: HostConfig) -> dict[str, Any]:
    """Convert a HostConfig object to a dictionary for serialization.

    Args:
    ----
        host_config: HostConfig object to convert

    Returns:
    -------
        Dictionary representation of the HostConfig

    """
    # Use Pydantic's model_dump to convert to dict with exclusion of empty values
    host_data = host_config.model_dump(exclude_none=True, exclude_unset=True)
    
    # Remove host_id from the serialized data since it's part of the key in the hosts dict
    if "host_id" in host_data:
        del host_data["host_id"]
    
    # Ensure validity days format is correct if days is available through to_days()
    if "validity" in host_data and host_config.validity:
        days_result = host_config.validity.to_days()
        if isinstance(days_result, Success):
            host_data["validity"] = {"days": days_result.unwrap()}
    
    return host_data
