"""Configuration management for ReactorCA."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yamale  # type: ignore
import yaml
from rich.console import Console

from reactor_ca.models import AlternativeNames, CAConfig, HostConfig, PasswordConfig, SubjectIdentity, ValidityConfig
from reactor_ca.paths import (
    ENV_CONFIG_DIR,
    ENV_ROOT_DIR,
    ENV_STORE_DIR,
    SCHEMAS_DIR,
)

# Module-level constants
CONSOLE = Console()


@dataclass
class Config:
    """Configuration class that manages the application's paths.

    A single instance of this class should be created at application startup
    and passed to components that need access to paths or configuration.
    """

    root_dir: Path
    config_dir: Path
    store_dir: Path

    @classmethod
    def create(
        cls: type["Config"], config_dir: str | None = None, store_dir: str | None = None, root_dir: str | None = None
    ) -> "Config":
        """Create a Config instance with the given paths or defaults.

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
            Config: Initialized configuration instance

        """
        # Resolve paths in order of priority: explicit args -> env vars -> defaults
        root = Path(root_dir) if root_dir else Path(os.environ.get(ENV_ROOT_DIR, "."))
        config = Path(config_dir) if config_dir else Path(os.environ.get(ENV_CONFIG_DIR, root / "config"))
        store = Path(store_dir) if store_dir else Path(os.environ.get(ENV_STORE_DIR, root / "store"))

        return cls(root_dir=root, config_dir=config, store_dir=store)

    @property
    def ca_dir(self: "Config") -> Path:
        """Get the CA directory."""
        return self.store_dir / "ca"

    @property
    def hosts_dir(self: "Config") -> Path:
        """Get the hosts directory."""
        return self.store_dir / "hosts"

    @property
    def ca_config_path(self: "Config") -> Path:
        """Get the CA config file path."""
        return self.config_dir / "ca.yaml"

    @property
    def hosts_config_path(self: "Config") -> Path:
        """Get the hosts config file path."""
        return self.config_dir / "hosts.yaml"

    @property
    def inventory_path(self: "Config") -> Path:
        """Get the inventory file path."""
        return self.store_dir / "inventory.yaml"

    def ca_cert_path(self: "Config") -> Path:
        """Get the CA certificate file path."""
        return self.ca_dir / "ca.crt"

    def ca_key_path(self: "Config") -> Path:
        """Get the CA key file path."""
        return self.ca_dir / "ca.key.enc"

    def ca_crl_path(self: "Config") -> Path:
        """Get the CA CRL file path."""
        return self.ca_dir / "ca.crl"

    def host_dir(self: "Config", hostname: str) -> Path:
        """Get directory for a specific host."""
        return self.hosts_dir / hostname

    def host_cert_path(self: "Config", hostname: str) -> Path:
        """Get certificate path for a specific host."""
        return self.host_dir(hostname) / "cert.crt"

    def host_key_path(self: "Config", hostname: str) -> Path:
        """Get key path for a specific host."""
        return self.host_dir(hostname) / "cert.key.enc"

    def ensure_dirs(self: "Config") -> None:
        """Create all necessary directories."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.hosts_dir.mkdir(parents=True, exist_ok=True)


class ConfigError(Exception):
    """Base exception for configuration errors."""

    pass


class ConfigNotFoundError(ConfigError):
    """Exception raised when a configuration file is not found."""

    pass


class ConfigValidationError(ConfigError):
    """Exception raised when a configuration file is invalid."""

    pass


def validate_config(config_path: Path, schema_name: str) -> tuple[bool, list[str]]:
    """Validate a configuration file against a schema.

    Args:
    ----
        config_path: Path to the configuration file
        schema_name: Name of the schema file

    Returns:
    -------
        Tuple of (is_valid, error_messages)

    """
    if not config_path.exists():
        return False, [f"Configuration file not found: {config_path}"]

    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.exists():
        return False, [f"Schema file not found: {schema_path}"]

    schema = yamale.make_schema(schema_path)
    data = yamale.make_data(config_path)

    try:
        yamale.validate(schema, data)
        return True, []
    except ValueError as e:
        return False, [str(error) for error in e.args[0]]


def load_yaml_file(file_path: Path) -> dict[str, Any]:
    """Load YAML file into a dictionary.

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
        return yaml.safe_load(f)


def save_yaml_file(data: dict[str, Any], file_path: Path) -> None:
    """Save dictionary to a YAML file.

    Args:
    ----
        data: Dictionary to save
        file_path: Path to save the YAML file

    """
    # Ensure the directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="locale") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load CA configuration.

    Args:
    ----
        config_path: Optional path to the configuration file.
            If not provided, a default Config is created and its ca_config_path is used.

    Returns:
    -------
        The loaded configuration dictionary.

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist.
        ConfigValidationError: If the configuration is invalid.
        ConfigError: If there's an error loading the configuration.

    """
    if config_path is None:
        config_path = Config.create().ca_config_path

    if not config_path.exists():
        CONSOLE.print(f"[bold red]Error:[/bold red] Configuration file not found: {config_path}")
        CONSOLE.print("Run 'ca config init' to create a default configuration.")
        raise ConfigNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, encoding="locale") as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            CONSOLE.print("[bold red]Error:[/bold red] Invalid configuration format")
            raise ConfigValidationError("Invalid configuration format")

        return config
    except Exception as e:
        CONSOLE.print(f"[bold red]Error loading configuration:[/bold red] {str(e)}")
        raise ConfigError(f"Error loading configuration: {str(e)}") from e


def load_hosts_config_dict(config_path: Path | None = None) -> dict[str, Any]:
    """Load hosts configuration as a dictionary.

    Args:
    ----
        config_path: Optional path to the hosts configuration file.
            If not provided, a default Config is created and its hosts_config_path is used.

    Returns:
    -------
        The loaded hosts configuration dictionary.

    """
    if config_path is None:
        config_path = Config.create().hosts_config_path

    if not config_path.exists():
        CONSOLE.print(f"[bold yellow]Warning:[/bold yellow] Hosts configuration file not found: {config_path}")
        return {"hosts": []}

    try:
        with open(config_path, encoding="locale") as f:
            hosts_config = yaml.safe_load(f)

        if not isinstance(hosts_config, dict):
            CONSOLE.print("[bold red]Error:[/bold red] Invalid hosts configuration format")
            return {"hosts": []}

        return hosts_config
    except Exception as e:
        CONSOLE.print(f"[bold red]Error loading hosts configuration:[/bold red] {str(e)}")
        return {"hosts": []}  # Return empty hosts list as fallback


def get_default_ca_config() -> dict[str, Any]:
    """Get default CA configuration dictionary."""
    return {
        "ca": {
            "common_name": "Reactor CA",
            "organization": "Reactor Homelab",
            "organization_unit": "IT",
            "country": "DE",
            "state": "Niedersachsen",
            "locality": "Hannover",
            "email": "admin@example.com",
            "key_algorithm": "RSA4096",
            "validity": {
                "years": 10,
            },
            "password": {
                "min_length": 12,
                "file": "",
                "env_var": "REACTOR_CA_PASSWORD",
            },
        }
    }


def get_default_hosts_config() -> dict[str, Any]:
    """Get default hosts configuration dictionary."""
    return {
        "hosts": [
            {
                "name": "server1.example.com",
                "common_name": "server1.example.com",
                "alternative_names": {
                    "dns": [
                        "www.example.com",
                        "api.example.com",
                    ],
                    "ip": [
                        "192.168.1.10",
                    ],
                },
                "export": {
                    "cert": "../path/to/export/cert/server1.pem",
                    "chain": "../path/to/export/cert/server1-chain.pem",
                },
                "deploy": {
                    "command": "cp ${cert} /etc/nginx/ssl/server1.pem "
                    + "&& cp ${private_key} /etc/nginx/ssl/server1.key && systemctl reload nginx",
                },
                "validity": {
                    "years": 1,
                },
                "key_algorithm": "RSA2048",
            },
        ]
    }


def create_default_config(config: Config | None = None) -> None:
    """Create default configuration files.

    Args:
    ----
        config: Optional Config instance to use for paths.
            If not provided, a default Config is created.

    """
    config = config or Config.create()

    # Create config directory if it doesn't exist
    config.config_dir.mkdir(parents=True, exist_ok=True)

    # Get default configurations
    ca_config = get_default_ca_config()
    hosts_config = get_default_hosts_config()

    # Write configuration files
    write_config_file(ca_config, config.ca_config_path, "ca")
    write_config_file(hosts_config, config.hosts_config_path, "hosts")

    CONSOLE.print("✅ Created default configuration files:")
    CONSOLE.print(f"   CA config: [bold]{config.ca_config_path}[/bold]")
    CONSOLE.print(f"   Hosts config: [bold]{config.hosts_config_path}[/bold]")
    CONSOLE.print("Please review and customize these files before initializing the CA.")


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


def load_ca_config(config_path: Path) -> CAConfig:
    """Load and validate CA configuration into a CAConfig object.

    Args:
    ----
        config_path: Path to the CA configuration file

    Returns:
    -------
        CAConfig object

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid

    """
    # Validate first
    valid, errors = validate_config(config_path, "ca_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid CA configuration:\n{error_message}")

    # Load the configuration
    config_dict = load_yaml_file(config_path)

    # Check if config is in the expected format (may be nested under 'ca' key)
    if "ca" in config_dict:
        config_dict = config_dict["ca"]

    # Convert dictionary to CAConfig
    validity_data = config_dict.get("validity") or {}
    validity_days = config_dict.get("validity_days")

    # Handle validity as either a dictionary or direct days value
    if isinstance(validity_data, dict):
        validity = ValidityConfig(days=validity_data.get("days"), years=validity_data.get("years"))
    else:
        validity = ValidityConfig(days=validity_days or validity_data)

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


def load_hosts_config(config_path: Path) -> dict[str, HostConfig]:
    """Load and validate hosts configuration into a dictionary of HostConfig objects.

    Args:
    ----
        config_path: Path to the hosts configuration file

    Returns:
    -------
        Dictionary mapping host names to HostConfig objects

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid

    """
    # Validate first
    valid, errors = validate_config(config_path, "hosts_config_schema.yaml")
    if not valid:
        error_message = "\n".join(errors)
        raise ConfigValidationError(f"Invalid hosts configuration:\n{error_message}")

    # Load the configuration
    config_dict = load_yaml_file(config_path)
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
    validity = _parse_validity_config(host_data)

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

    # Handle both direct lists and those nested under 'alternative_names'
    # DNS names
    if "dns_names" in host_data:
        dns_names = host_data.get("dns_names", [])
    elif isinstance(alt_names, dict) and "dns" in alt_names:
        dns_names = alt_names.get("dns", [])

    # IP addresses
    if "ip_addresses" in host_data:
        ip_addresses = host_data.get("ip_addresses", [])
    elif isinstance(alt_names, dict) and "ip" in alt_names:
        ip_addresses = alt_names.get("ip", [])

    # Email addresses
    if "email_addresses" in host_data:
        email_addresses = host_data.get("email_addresses", [])
    elif isinstance(alt_names, dict) and "email" in alt_names:
        email_addresses = alt_names.get("email", [])

    # URIs
    if "uris" in host_data:
        uris = host_data.get("uris", [])
    elif isinstance(alt_names, dict) and "uri" in alt_names:
        uris = alt_names.get("uri", [])

    # Directory names
    if "directory_names" in host_data:
        directory_names = host_data.get("directory_names", [])
    elif isinstance(alt_names, dict) and "directory_name" in alt_names:
        directory_names = alt_names.get("directory_name", [])

    # Registered IDs
    if "registered_ids" in host_data:
        registered_ids = host_data.get("registered_ids", [])
    elif isinstance(alt_names, dict) and "registered_id" in alt_names:
        registered_ids = alt_names.get("registered_id", [])

    # Other names
    if "other_names" in host_data:
        other_names = host_data.get("other_names", [])
    elif isinstance(alt_names, dict) and "other_name" in alt_names:
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


def _parse_validity_config(host_data: dict[str, Any]) -> ValidityConfig:
    """Parse validity configuration from host data.

    Args:
    ----
        host_data: Dictionary containing host configuration

    Returns:
    -------
        ValidityConfig object

    """
    validity_data = host_data.get("validity", {})
    days_valid = host_data.get("days_valid")

    if isinstance(validity_data, dict):
        return ValidityConfig(days=validity_data.get("days"), years=validity_data.get("years"))
    else:
        return ValidityConfig(days=days_valid or validity_data or 365)


def get_host_config(host_name: str, config_path: Path | None = None) -> HostConfig:
    """Get the configuration for a specific host.

    Args:
    ----
        host_name: Name of the host to get configuration for
        config_path: Path to the hosts configuration file.
            If not provided, a default Config is created and its hosts_config_path is used.

    Returns:
    -------
        HostConfig object for the specified host

    Raises:
    ------
        ConfigNotFoundError: If the configuration file doesn't exist
        ConfigValidationError: If the configuration is invalid
        ValueError: If the host is not found

    """
    if config_path is None:
        config_path = Config.create().hosts_config_path

    hosts_dict = load_hosts_config(config_path)

    if host_name not in hosts_dict:
        raise ValueError(f"Host not found in configuration: {host_name}")

    return hosts_dict[host_name]


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

    with open(config_path, "w", encoding="locale") as f:
        for line in header:
            f.write(line + "\n")
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


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


def save_ca_config(ca_config: CAConfig, config_path: Path) -> None:
    """Save CA configuration to a file.

    Args:
    ----
        ca_config: CAConfig object
        config_path: Path to save the CA configuration file

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
    write_config_file(config_dict, config_path, "ca")


def save_hosts_config(hosts_dict: dict[str, HostConfig], config_path: Path) -> None:
    """Save hosts configuration to a file.

    Args:
    ----
        hosts_dict: Dictionary mapping host names to HostConfig objects
        config_path: Path to save the hosts configuration file

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
    write_config_file({"hosts": hosts_data}, config_path, "hosts")


def validate_configs(config: Config | None = None) -> bool:
    """Validate all configuration files against schemas.

    Args:
    ----
        config: Optional Config instance to use for paths.
            If not provided, a default Config is created.

    Returns:
    -------
        True if all validations pass, False otherwise.

    """
    config = config or Config.create()
    return validate_config_files(config.ca_config_path, config.hosts_config_path)


def validate_config_before_operation(config: Config | None = None) -> bool:
    """Quick validation check before performing operations.

    Args:
    ----
        config: Optional Config instance to use for paths.
            If not provided, a default Config is created.

    Returns:
    -------
        True if validation passes, False otherwise.

    """
    try:
        return validate_configs(config)
    except Exception as e:
        CONSOLE.print(f"[bold red]Error validating configuration:[/bold red] {str(e)}")
        return False


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
    ca_valid, ca_errors = validate_config(ca_config_path, "ca_config_schema.yaml")
    if not ca_valid:
        CONSOLE.print("[bold red]CA configuration validation failed:[/bold red]")
        for error in ca_errors:
            CONSOLE.print(f"  - {error}")
        return False

    CONSOLE.print("✅ CA configuration is valid")

    # Validate hosts config if it exists
    if hosts_config_path.exists():
        hosts_valid, hosts_errors = validate_config(hosts_config_path, "hosts_config_schema.yaml")
        if not hosts_valid:
            CONSOLE.print("[bold red]Hosts configuration validation failed:[/bold red]")
            for error in hosts_errors:
                CONSOLE.print(f"  - {error}")
            return False

        CONSOLE.print("✅ Hosts configuration is valid")

    return True


def init_config_files(ca_config_path: Path, hosts_config_path: Path, force: bool = False) -> None:
    """Initialize default configuration files.

    Args:
    ----
        ca_config_path: Path to create the CA configuration file
        hosts_config_path: Path to create the hosts configuration file
        force: Whether to overwrite existing files

    """
    # Create CA config if needed
    if not ca_config_path.exists() or force:
        ca_config = get_default_ca_config()
        save_yaml_file(ca_config, ca_config_path)
        CONSOLE.print(f"[green]Created CA configuration file: {ca_config_path}[/green]")
    else:
        CONSOLE.print(f"[yellow]CA configuration file already exists: {ca_config_path}[/yellow]")

    # Create hosts config if needed
    if not hosts_config_path.exists() or force:
        hosts_config = get_default_hosts_config()
        save_yaml_file(hosts_config, hosts_config_path)
        CONSOLE.print(f"[green]Created hosts configuration file: {hosts_config_path}[/green]")
    else:
        CONSOLE.print(f"[yellow]Hosts configuration file already exists: {hosts_config_path}[/yellow]")
