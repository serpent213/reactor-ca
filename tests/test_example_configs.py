"""Test that example configs match the schema."""

from pathlib import Path

from reactor_ca.config import validate_config


def test_example_ca_config_is_valid() -> None:
    """Test that the example CA config is valid against the schema."""
    # Get the path to the example CA config
    example_ca_config_path = Path("example_config/ca.yaml")

    # Ensure the file exists
    assert example_ca_config_path.exists(), "Example CA config file does not exist"

    # Validate against schema
    valid, errors = validate_config(example_ca_config_path, "ca_config_schema.yaml")

    # Check result
    assert valid is True, f"Example CA config does not validate against schema: {errors}"


def test_example_hosts_config_is_valid() -> None:
    """Test that the example hosts config is valid against the schema."""
    # Get the path to the example hosts config
    example_hosts_config_path = Path("example_config/hosts.yaml")

    # Ensure the file exists
    assert example_hosts_config_path.exists(), "Example hosts config file does not exist"

    # Validate against schema
    valid, errors = validate_config(example_hosts_config_path, "hosts_config_schema.yaml")

    # Check result
    assert valid is True, f"Example hosts config does not validate against schema: {errors}"
