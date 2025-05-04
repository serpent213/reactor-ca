"""Configuration operations for ReactorCA."""

import os
from pathlib import Path
from typing import Any, cast

import yamale  # type: ignore
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
    DeploymentConfig,
    ExportConfig,
    HostConfig,
    PasswordConfig,
    SubjectIdentity,
    ValidityConfig,
)
from reactor_ca.paths import SCHEMAS_DIR, ensure_dirs, get_ca_config_path, get_hosts_config_path

CONSOLE = Console()
yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


# Exception definitions
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
    """Validate a YAML file against a schema.

    Args:
    ----
        file_path: Path to the configuration file
        schema_name: Name of the schema file

    Returns:
    -------
        Tuple of (is_valid, error_messages)
    """
    if not file_path.exists():
        return False, [f"Configuration file not found: {file_path}"]

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
    """Load YAML file into a dictionary, preserving comments.

    Args:
    ----
        file_path: Path to the YAML file

    Returns:
    -------
        Dictionary containing the YAML data

    Raises:
    ------
        ConfigNotFoundError: If the file doesn't exist
    """
    if not file_path.exists():
        raise ConfigNotFoundError(f"File not found: {file_path}")

    with open(file_path, encoding="locale") as f:
        data = yaml.load(f)

    # Ensure we return a dict, even if the file is empty
    return data or {}


def save_yaml(data: dict[str, Any], file_path: Path) -> None:
    """Save dictionary to a YAML file, preserving comments.

    Args:
    ----
        data: Dictionary to save
        file_path: Path to save the YAML file
    """
    # Ensure the directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="locale") as f:
        yaml.dump(data, f)


def load_ca_config(config_dir: Path) -> CAConfig:
    """Load and validate CA configuration into a CAConfig object.

    Args:
    ----
        config_dir: Path to the configuration directory

    Returns:
    -------
        CAConfig object

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid
    """
    ca_config_path = get_ca_config_path(config_dir)

    # Validate first
    valid, errors = validate_yaml(ca_config_path, "ca_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid CA configuration:\n{error_message}")

    # Load the configuration
    config_dict = load_yaml(ca_config_path)

    # Check if config is in the expected format (may be nested under 'ca' key)
    if "ca" in config_dict:
        config_dict = config_dict["ca"]

    # Convert dictionary to CAConfig
    validity = _parse_validity_config(config_dict, DEFAULT_CA_VALIDITY_DAYS)

    password_config = config_dict.get("password", {})
    password = PasswordConfig(
        min_length=password_config.get("min_length", 12),
        file=password_config.get("file", ""),
        env_var=password_config.get("env_var", "REACTOR_CA_PASSWORD"),
    )

    try:
        return CAConfig(
            common_name=config_dict["common_name"],
            organization=config_dict["organization"],
            organization_unit=config_dict.get("organization_unit", ""),
            country=config_dict["country"],
            state=config_dict["state"],
            locality=config_dict["locality"],
            email=config_dict["email"],
            key_algorithm=config_dict.get("key_algorithm", "RSA2048"),
            validity=validity,
            password=password,
            hash_algorithm=config_dict.get("hash_algorithm", "SHA256"),
        )
    except KeyError as e:
        CONSOLE.print(f"[bold red]Error:[/bold red] Missing required field in configuration: {e}")
        raise ConfigValidationError(f"Missing required field in configuration: {e}") from e


def load_hosts_config(config_dir: Path) -> dict[str, HostConfig]:
    """Load and validate hosts configuration into a dictionary of HostConfig objects.

    Args:
    ----
        config_dir: Path to the configuration directory

    Returns:
    -------
        Dictionary mapping host names to HostConfig objects

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid
    """
    hosts_config_path = get_hosts_config_path(config_dir)

    # Validate first
    valid, errors = validate_yaml(hosts_config_path, "hosts_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid hosts configuration:\n{error_message}")

    # Load the configuration
    config_dict = load_yaml(hosts_config_path)
    hosts_dict = {}
    hosts_data = config_dict.get("hosts", {})

    # Convert a list of host dicts to a dict keyed by name
    if isinstance(hosts_data, list):
        hosts_map = {}
        for host in hosts_data:
            if "name" in host:
                hosts_map[host["name"]] = host.copy()
            else:
                CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Host entry missing 'name' field: {host}")
        hosts_data = hosts_map

    try:
        for host_name, host_data in hosts_data.items():
            hosts_dict[host_name] = _parse_host_config(host_name, host_data)
    except (AttributeError, TypeError) as e:
        CONSOLE.print(f"[bold red]Error processing hosts config:[/bold red] {e}")
        raise ConfigValidationError(f"Failed to process hosts configuration: {e}") from e

    return hosts_dict


def get_host_config(config_dir: Path, host_name: str) -> HostConfig:
    """Get the configuration for a specific host.

    Args:
    ----
        config_dir: Path to the configuration directory
        host_name: Name of the host to get configuration for

    Returns:
    -------
        HostConfig object for the specified host

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid
        ValueError: If the host is not found
    """
    hosts_dict = load_hosts_config(config_dir)

    if host_name not in hosts_dict:
        raise ValueError(f"Host not found in configuration: {host_name}")

    return hosts_dict[host_name]


def _parse_host_config(host_name: str, host_data: dict[str, Any]) -> HostConfig:
    """Parse host configuration data into a HostConfig object.

    Args:
    ----
        host_name: Name of the host
        host_data: Dictionary containing host configuration

    Returns:
    -------
        HostConfig object
    """
    # Parse alternative names
    alt_names = _parse_alternative_names(host_data)

    # Parse validity period
    validity = _parse_validity_config(host_data, DEFAULT_HOST_VALIDITY_DAYS)

    # Parse export config
    export = _parse_export_config(host_data)

    # Parse deploy config
    deploy = _parse_deploy_config(host_data)

    # Get common name, defaulting to the host_name if not specified
    common_name = host_data.get("common_name", host_name)

    # Create host config
    return HostConfig(
        name=host_name,
        common_name=common_name,
        organization=host_data.get("organization"),
        organization_unit=host_data.get("organization_unit"),
        country=host_data.get("country"),
        state=host_data.get("state"),
        locality=host_data.get("locality"),
        email=host_data.get("email"),
        alternative_names=alt_names,
        validity=validity,
        export=export,
        deploy=deploy,
        key_algorithm=host_data.get("key_algorithm", "RSA2048"),
        hash_algorithm=host_data.get("hash_algorithm"),
    )


def _parse_alternative_names(host_data: dict[str, Any]) -> AlternativeNames | None:
    """Parse alternative names from host configuration.

    Args:
    ----
        host_data: Dictionary containing host configuration

    Returns:
    -------
        AlternativeNames object or None if no alternative names are specified
    """
    # Initialize all SAN types
    dns_names = []
    ip_addresses = []
    email_addresses = []
    uris = []
    directory_names = []
    registered_ids = []
    other_names = []

    alt_names = host_data.get("alternative_names", {})
    if not isinstance(alt_names, dict):
        return None

    # Get values from standard schema
    dns_names = alt_names.get("dns", [])
    ip_addresses = alt_names.get("ip", [])
    email_addresses = alt_names.get("email", [])
    uris = alt_names.get("uri", [])
    directory_names = alt_names.get("directory_name", [])
    registered_ids = alt_names.get("registered_id", [])
    other_names = alt_names.get("other_name", [])

    # If any SAN type is specified, create and return AlternativeNames object
    if any([dns_names, ip_addresses, email_addresses, uris, directory_names, registered_ids, other_names]):
        return AlternativeNames(
            dns=dns_names,
            ip=ip_addresses,
            email=email_addresses,
            uri=uris,
            directory_name=directory_names,
            registered_id=registered_ids,
            other_name=other_names,
        )

    return None


def _parse_validity_config(config_data: dict[str, Any], default_days: int) -> ValidityConfig:
    """Parse validity configuration from configuration data.

    Args:
    ----
        config_data: Dictionary containing configuration
        default_days: Default validity period in days

    Returns:
    -------
        ValidityConfig object
    """
    validity_data = config_data.get("validity", {})

    if isinstance(validity_data, dict):
        return ValidityConfig(days=validity_data.get("days"), years=validity_data.get("years"))
    else:
        return ValidityConfig(days=validity_data or default_days)


def _parse_export_config(host_data: dict[str, Any]) -> ExportConfig | None:
    """Parse export configuration from host data.

    Args:
    ----
        host_data: Dictionary containing host configuration

    Returns:
    -------
        ExportConfig object or None if no export configuration is specified
    """
    export_data = host_data.get("export", {})

    if not export_data:
        return None

    return ExportConfig(
        cert=export_data.get("cert"),
        chain=export_data.get("chain"),
    )


def _parse_deploy_config(host_data: dict[str, Any]) -> DeploymentConfig | None:
    """Parse deployment configuration from host data.

    Args:
    ----
        host_data: Dictionary containing host configuration

    Returns:
    -------
        DeploymentConfig object or None if no deployment configuration is specified
    """
    deploy_data = host_data.get("deploy", {})

    if not deploy_data or not deploy_data.get("command"):
        return None

    return DeploymentConfig(
        command=deploy_data.get("command", ""),
    )


def get_password(
    password: str | None = None, password_file: str | None = None, password_env: str | None = None
) -> str | None:
    """Get password from provided options.

    This function tries to get a password from one of the provided sources,
    in the following order: direct password, password file, environment variable.

    Args:
    ----
        password: Password provided directly
        password_file: Path to file containing the password
        password_env: Name of environment variable containing the password

    Returns:
    -------
        Password or None if no password is provided

    Raises:
    ------
        ValueError: If multiple password options are provided
        FileNotFoundError: If the password file doesn't exist
    """
    provided_options = [opt for opt in [password, password_file, password_env] if opt is not None]

    if len(provided_options) > 1:
        raise ValueError("Only one of password, password_file, or password_env can be provided")

    if password is not None:
        return password

    if password_file is not None:
        if not os.path.exists(password_file):
            raise FileNotFoundError(f"Password file not found: {password_file}")
        with open(password_file, encoding="locale") as f:
            return f.read().strip()

    if password_env is not None:
        env_value = os.environ.get(password_env)
        if env_value is None:
            raise ValueError(f"Environment variable not set: {password_env}")
        return env_value

    return None


def write_config_file(config: dict, config_path: Path, config_type: str = "ca") -> None:
    """Write configuration to file with standard header.

    Args:
    ----
        config: Configuration dictionary to write
        config_path: Path to save the configuration file
        config_type: Type of configuration ("ca" or "hosts")
    """
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


def create_default_config(config_dir: Path, store_dir: Path) -> None:
    """Create default configuration files.

    Args:
    ----
        config_dir: Path to configuration directory
        store_dir: Path to store directory
    """
    # Create necessary directories
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


def update_config_with_metadata(
    config: dict, cert_metadata: SubjectIdentity, key_algorithm: str, fallback_to_default: bool = False
) -> None:
    """Update configuration with certificate metadata.

    Args:
    ----
        config: Configuration dictionary to update
        cert_metadata: Certificate metadata to use for updating
        key_algorithm: Key algorithm to use
        fallback_to_default: Whether to use defaults if metadata is missing
    """

    # Helper function to update a config field if the metadata exists
    def update_field(config_field: str, metadata_field: str) -> None:
        metadata_value = getattr(cert_metadata, metadata_field)
        if fallback_to_default:
            config["ca"][config_field] = metadata_value or config["ca"][config_field]
        elif metadata_value:
            config["ca"][config_field] = metadata_value

    update_field("common_name", "common_name")
    update_field("organization", "organization")
    update_field("organization_unit", "organization_unit")
    update_field("country", "country")
    update_field("state", "state")
    update_field("locality", "locality")
    update_field("email", "email")

    # Always update key algorithm
    config["ca"]["key_algorithm"] = key_algorithm


def save_ca_config(ca_config: CAConfig, config_dir: Path) -> None:
    """Save CA configuration to a file.

    Args:
    ----
        ca_config: CAConfig object
        config_dir: Path to the configuration directory
    """
    # Convert CAConfig to dictionary
    config_dict = {
        "ca": {
            "common_name": ca_config.common_name,
            "organization": ca_config.organization,
            "organization_unit": ca_config.organization_unit,
            "country": ca_config.country,
            "state": ca_config.state,
            "locality": ca_config.locality,
            "email": ca_config.email,
            "key_algorithm": ca_config.key_algorithm,
            "validity": {
                "days": ca_config.validity.to_days(),
            },
            "hash_algorithm": ca_config.hash_algorithm,
            "password": {
                "min_length": ca_config.password.min_length,
                "file": ca_config.password.file,
                "env_var": ca_config.password.env_var,
            },
        }
    }

    # Write config to file
    ca_config_path = get_ca_config_path(config_dir)
    write_config_file(config_dict, ca_config_path, "ca")


def save_hosts_config(hosts_dict: dict[str, HostConfig], config_dir: Path) -> None:
    """Save hosts configuration to a file.

    Args:
    ----
        hosts_dict: Dictionary mapping host names to HostConfig objects
        config_dir: Path to the configuration directory
    """
    # Convert HostConfig objects to dictionary
    hosts_data = {}
    for host_name, host_config in hosts_dict.items():
        host_data = {
            "common_name": host_config.common_name,
            "key_algorithm": host_config.key_algorithm,
            "validity": {
                "days": host_config.validity.to_days(),
            },
        }

        # Add optional fields if present
        if host_config.organization:
            host_data["organization"] = host_config.organization
        if host_config.organization_unit:
            host_data["organization_unit"] = host_config.organization_unit
        if host_config.country:
            host_data["country"] = host_config.country
        if host_config.state:
            host_data["state"] = host_config.state
        if host_config.locality:
            host_data["locality"] = host_config.locality
        if host_config.email:
            host_data["email"] = host_config.email

        # Add alternative names if present
        if host_config.alternative_names:
            alt_names_dict: dict[str, list[str]] = {}
            host_data["alternative_names"] = alt_names_dict

            # Add all supported SAN types
            if host_config.alternative_names.dns:
                alt_names_dict["dns"] = host_config.alternative_names.dns
            if host_config.alternative_names.ip:
                alt_names_dict["ip"] = host_config.alternative_names.ip
            if host_config.alternative_names.email:
                alt_names_dict["email"] = host_config.alternative_names.email
            if host_config.alternative_names.uri:
                alt_names_dict["uri"] = host_config.alternative_names.uri
            if host_config.alternative_names.directory_name:
                alt_names_dict["directory_name"] = host_config.alternative_names.directory_name
            if host_config.alternative_names.registered_id:
                alt_names_dict["registered_id"] = host_config.alternative_names.registered_id
            if host_config.alternative_names.other_name:
                alt_names_dict["other_name"] = host_config.alternative_names.other_name

        hosts_data[host_name] = host_data

    # Write hosts config to file
    hosts_config_path = get_hosts_config_path(config_dir)
    write_config_file({"hosts": hosts_data}, hosts_config_path, "hosts")


def validate_config_files(ca_config_path: Path, hosts_config_path: Path) -> bool:
    """Validate configuration files.

    Args:
    ----
        ca_config_path: Path to the CA configuration file
        hosts_config_path: Path to the hosts configuration file

    Returns:
    -------
        True if all configurations are valid, False otherwise
    """
    # Check if CA config exists (required)
    if not ca_config_path.exists():
        CONSOLE.print(f"[bold red]Error:[/bold red] CA configuration file not found: {ca_config_path}")
        CONSOLE.print("Run 'ca config init' to create a default configuration.")
        return False

    # Hosts config is optional
    if not hosts_config_path.exists():
        CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {hosts_config_path}")
        CONSOLE.print("You may want to create a hosts configuration to issue certificates.")

    # Validate CA config
    ca_valid, ca_errors = validate_yaml(ca_config_path, "ca_config_schema.yaml")
    if not ca_valid:
        CONSOLE.print("[bold red]CA configuration validation failed:[/bold red]")
        for error in ca_errors:
            CONSOLE.print(f"  - {error}")
        return False

    CONSOLE.print("✅ CA configuration is valid")

    # Validate hosts config if it exists
    if hosts_config_path.exists():
        hosts_valid, hosts_errors = validate_yaml(hosts_config_path, "hosts_config_schema.yaml")
        if not hosts_valid:
            CONSOLE.print("[bold red]Hosts configuration validation failed:[/bold red]")
            for error in hosts_errors:
                CONSOLE.print(f"  - {error}")
            return False

        CONSOLE.print("✅ Hosts configuration is valid")

    return True


def init_config_files(config_dir: Path, store_dir: Path, force: bool = False) -> None:
    """Initialize default configuration files.

    Args:
    ----
        config_dir: Path to configuration directory
        store_dir: Path to store directory
        force: Whether to overwrite existing files
    """
    # Get paths
    ca_config_path = get_ca_config_path(config_dir)
    hosts_config_path = get_hosts_config_path(config_dir)

    # Create CA config if needed
    if not ca_config_path.exists() or force:
        ca_config = get_default_ca_config()
        save_yaml(ca_config, ca_config_path)
        CONSOLE.print(f"[green]Created CA configuration file: {ca_config_path}[/green]")
    else:
        CONSOLE.print(f"[yellow]CA configuration file already exists: {ca_config_path}[/yellow]")

    # Create hosts config if needed
    if not hosts_config_path.exists() or force:
        hosts_config = get_default_hosts_config()
        save_yaml(hosts_config, hosts_config_path)
        CONSOLE.print(f"[green]Created hosts configuration file: {hosts_config_path}[/green]")
    else:
        CONSOLE.print(f"[yellow]Hosts configuration file already exists: {hosts_config_path}[/yellow]")
