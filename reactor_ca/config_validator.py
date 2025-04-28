"""Configuration validation for ReactorCA."""

from pathlib import Path
from typing import List, Tuple

import yamale
from rich.console import Console

console = Console()


def validate_ca_config(config_path: str) -> Tuple[bool, List[str]]:
    """
    Validate CA configuration file against the schema.

    Args:
        config_path: Path to the CA configuration file.

    Returns:
        A tuple containing a boolean indicating if validation passed
        and a list of validation error messages.
    """
    try:
        # Get the schema file path relative to this module
        schema_dir = Path(__file__).parent / "schemas"
        schema_path = schema_dir / "ca_config_schema.yaml"

        # Load the schema
        schema = yamale.make_schema(str(schema_path))

        # Load the data
        data = yamale.make_data(config_path)

        # Validate
        yamale.validate(schema, data)
        return True, []
    except yamale.YamaleError as e:
        # Extract error messages
        error_msgs = []
        for result in e.results:
            for error in result.errors:
                error_msgs.append(str(error))
        return False, error_msgs
    except Exception as e:
        return False, [f"Unexpected error during validation: {str(e)}"]


def validate_hosts_config(hosts_path: str) -> Tuple[bool, List[str]]:
    """
    Validate hosts configuration file against the schema.

    Args:
        hosts_path: Path to the hosts configuration file.

    Returns:
        A tuple containing a boolean indicating if validation passed
        and a list of validation error messages.
    """
    try:
        # Get the schema file path relative to this module
        schema_dir = Path(__file__).parent / "schemas"
        schema_path = schema_dir / "hosts_schema.yaml"

        # Load the schema
        schema = yamale.make_schema(str(schema_path))

        # Load the data
        data = yamale.make_data(hosts_path)

        # Validate
        yamale.validate(schema, data)
        return True, []
    except yamale.YamaleError as e:
        # Extract error messages
        error_msgs = []
        for result in e.results:
            for error in result.errors:
                error_msgs.append(str(error))
        return False, error_msgs
    except Exception as e:
        return False, [f"Unexpected error during validation: {str(e)}"]


def validate_configs() -> bool:
    """
    Validate all configuration files.

    Returns:
        True if all validations pass, False otherwise.
    """
    config_dir = Path("config")
    ca_config_path = config_dir / "ca_config.yaml"
    hosts_config_path = config_dir / "hosts.yaml"

    all_valid = True

    # Check if files exist
    if not ca_config_path.exists():
        console.print(
            f"[bold red]Error:[/bold red] CA configuration file not found: {ca_config_path}"
        )
        console.print("Run 'ca config init' to create a default configuration.")
        return False

    if not hosts_config_path.exists():
        console.print(
            "[bold yellow]Warning:[/bold yellow] "
            + "Hosts configuration file not found: {hosts_config_path}"
        )
        console.print("You may want to create a hosts configuration to issue certificates.")

    # Validate CA config
    ca_valid, ca_errors = validate_ca_config(str(ca_config_path))
    if not ca_valid:
        console.print("[bold red]CA configuration validation failed:[/bold red]")
        for error in ca_errors:
            console.print(f"  - {error}")
        all_valid = False
    else:
        console.print("✅ CA configuration is valid")

    # Validate hosts config if it exists
    if hosts_config_path.exists():
        hosts_valid, hosts_errors = validate_hosts_config(str(hosts_config_path))
        if not hosts_valid:
            console.print("[bold red]Hosts configuration validation failed:[/bold red]")
            for error in hosts_errors:
                console.print(f"  - {error}")
            all_valid = False
        else:
            console.print("✅ Hosts configuration is valid")

    return all_valid


def validate_config_before_operation() -> bool:
    """
    Quick validation check before performing operations.

    Returns:
        True if validation passes, False otherwise.
    """
    try:
        return validate_configs()
    except Exception as e:
        console.print(f"[bold red]Error validating configuration:[/bold red] {str(e)}")
        return False
