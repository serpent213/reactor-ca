"""Configuration operations for ReactorCA."""

import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from rich.console import Console
from ruamel.yaml import YAML
from ruamel.yaml.nodes import ScalarNode
from ruamel.yaml.representer import Representer

from reactor_ca.defaults import get_default_ca_config, get_default_hosts_config
from reactor_ca.models import CAConfig, Config, HostConfig
from reactor_ca.paths import get_ca_config_path, get_hosts_config_path
from reactor_ca.result import Failure, Result, Success
from reactor_ca.types import HashAlgorithm, KeyAlgorithm

CONSOLE = Console()
yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


def enum_representer(dumper: Representer, data: Enum) -> ScalarNode:
    """Convert enum to string YAML representation."""
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data.value))


yaml.representer.add_representer(KeyAlgorithm, enum_representer)
yaml.representer.add_representer(HashAlgorithm, enum_representer)


def create(config_path: Path, force: bool = False) -> Result[Config, str]:
    """Create configuration files and directories with default values.

    Args:
    ----
        config_path: Path to config directory
        force: If True, overwrite existing configuration files.

    Returns:
    -------
        Result with Config object or error message

    """
    try:
        config_path.mkdir(parents=True, exist_ok=True)

        ca_config_file_path = get_ca_config_path(config_path)
        if force or not ca_config_file_path.exists():
            _write_config_file(get_default_ca_config(), ca_config_file_path, "ca")
            CONSOLE.print(f"Created CA config at {ca_config_file_path}")
        else:
            CONSOLE.print(f"CA config already exists at {ca_config_file_path}, skipping.")

        hosts_config_file_path = get_hosts_config_path(config_path)
        if force or not hosts_config_file_path.exists():
            _write_config_file(get_default_hosts_config(), hosts_config_file_path, "hosts")
            CONSOLE.print(f"Created hosts config at {hosts_config_file_path}")
        else:
            CONSOLE.print(f"Hosts config already exists at {hosts_config_file_path}, skipping.")

        return init(config_path)
    except Exception as e:
        return Failure(f"Failed to create configuration: {e!s}")


def init(config_path: Path) -> Result[Config, str]:
    """Initialize a Config object from existing configuration files.

    Args:
    ----
        config_path: Path to config directory

    Returns:
    -------
        Result with Config object or error message

    """
    if not config_path.is_dir():
        return Failure(f"Config directory does not exist: {config_path}")

    ca_config_result = _load_ca_config(config_path)
    if isinstance(ca_config_result, Failure):
        return ca_config_result

    hosts_config_result = _load_hosts_config(config_path)
    if isinstance(hosts_config_result, Failure):
        return hosts_config_result

    return Success(
        Config(config_path=config_path, ca_config=ca_config_result.value, hosts_config=hosts_config_result.value)
    )


def validate(config_path: Path) -> Result[None, str]:
    """Validate configuration files.

    Args:
    ----
        config_path: Path to the configuration directory

    Returns:
    -------
        Result with None if all configurations are valid, or error message

    """
    has_errors = False
    for conf_type, path_func in [("ca", get_ca_config_path), ("hosts", get_hosts_config_path)]:
        path = path_func(config_path)
        if not path.exists():
            if conf_type == "ca":
                CONSOLE.print(f"[bold red]Error:[/bold red] Required CA config not found: {path}")
                has_errors = True
            continue

        validation = _validate_yaml(path, conf_type)
        if isinstance(validation, Failure):
            CONSOLE.print(f"[bold red]{conf_type.title()} configuration validation failed:[/bold red]")
            for error in validation.error:
                CONSOLE.print(f"  - {error}")
            has_errors = True
        else:
            CONSOLE.print(f"✅ {conf_type.title()} configuration is valid")

    return Failure("Validation failed") if has_errors else Success(None)


def get_host_config(config: Config, host_id: str) -> Result[HostConfig, str]:
    """Get the configuration for a specific host.

    Args:
    ----
        config: Config object
        host_id: ID of the host to get configuration for

    Returns:
    -------
        Result with HostConfig object or error message

    """
    if not config.hosts_config:
        return Failure("No hosts configuration available")
    if host_id not in config.hosts_config:
        return Failure(f"Host '{host_id}' not found in configuration")
    return Success(config.hosts_config[host_id])


def _validate_yaml(file_path: Path, config_type: str) -> Result[None, list[str]]:
    """Validate a YAML file using Pydantic models."""
    try:
        with file_path.open(encoding="locale") as f:
            data = yaml.load(f) or {}

        if config_type == "ca":
            CAConfig.model_validate(data.get("ca", {}))
        elif config_type == "hosts":
            for host_id, host_data in data.get("hosts", {}).items():
                HostConfig.model_validate({**host_data, "host_id": host_id})
        else:
            return Failure([f"Unknown configuration type: {config_type}"])
        return Success(None)
    except ValidationError as e:
        return Failure([f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in json.loads(e.json())])
    except Exception as e:
        return Failure([f"Error validating {file_path}: {e!s}"])


def _load_ca_config(config_path: Path) -> Result[CAConfig | None, str]:
    """Load and validate CA configuration."""
    ca_config_path = get_ca_config_path(config_path)
    if not ca_config_path.exists():
        return Failure("CA configuration file not found.")

    validation_result = _validate_yaml(ca_config_path, "ca")
    if isinstance(validation_result, Failure):
        return Failure(f"Invalid CA configuration:\n" + "\n".join(validation_result.error))

    try:
        with ca_config_path.open(encoding="locale") as f:
            data = yaml.load(f) or {}
        return Success(CAConfig.model_validate(data.get("ca", {})))
    except Exception as e:
        return Failure(f"Error loading CA configuration: {e!s}")


def _load_hosts_config(config_path: Path) -> Result[dict[str, HostConfig], str]:
    """Load and validate hosts configuration."""
    hosts_config_path = get_hosts_config_path(config_path)
    if not hosts_config_path.exists():
        return Success({})  # No hosts file is valid

    validation_result = _validate_yaml(hosts_config_path, "hosts")
    if isinstance(validation_result, Failure):
        return Failure(f"Invalid hosts configuration:\n" + "\n".join(validation_result.error))

    try:
        with hosts_config_path.open(encoding="locale") as f:
            data = yaml.load(f) or {}

        hosts_data = data.get("hosts", {})
        hosts_dict = {
            host_id: HostConfig.model_validate({**host_data, "host_id": host_id})
            for host_id, host_data in hosts_data.items()
        }
        return Success(hosts_dict)
    except Exception as e:
        return Failure(f"Error loading hosts configuration: {e!s}")


def _write_config_file(config_data: dict[str, Any], path: Path, config_type: str) -> None:
    """Write configuration dictionary to a YAML file with a header."""
    headers = {
        "ca": "# ReactorCA: Certificate Authority Configuration\n\n",
        "hosts": "# ReactorCA: Host Certificate Configuration\n\n",
    }
    header = headers.get(config_type, "")

    with path.open("w", encoding="locale") as f:
        f.write(header)
        yaml.dump(config_data, f)
