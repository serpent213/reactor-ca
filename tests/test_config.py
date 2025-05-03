"""Tests for the configuration and validator."""

import os
import tempfile
from pathlib import Path

import yaml

from reactor_ca.config import Config, create_default_config, validate_config


def test_validate_ca_config_valid() -> None:
    """Test validating a valid CA configuration using the config.validate_config function."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        valid_config = {
            "ca": {
                "common_name": "Test CA",
                "organization": "Test Org",
                "organization_unit": "IT",
                "country": "US",
                "state": "Test State",
                "locality": "Test City",
                "email": "test@example.com",
                "key_algorithm": "RSA4096",
                "validity": {
                    "years": 10,
                },
                "password": {
                    "min_length": 12,
                    "file": "",
                    "env_var": "TEST_CA_PASSWORD",
                },
            }
        }
        yaml.dump(valid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "ca_config_schema.yaml")
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_ca_config_invalid() -> None:
    """Test validating an invalid CA configuration."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "ca": {
                "common_name": "Test CA",
                "organization": "Test Org",
                "organization_unit": "IT",
                # Missing required fields
                # "country": "US",
                "state": "Test State",
                "locality": "Test City",
                "email": "test@example.com",
                "key_algorithm": "RSA4096",
                "validity": {
                    "years": 10,
                },
                "password": {
                    "min_length": 12,
                },
            }
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "ca_config_schema.yaml")
        assert not valid
        assert errors


def test_validate_hosts_config_valid_rsa2048() -> None:
    """Test validating a valid hosts configuration (RSA2048)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        valid_config = {
            "hosts": [
                {
                    "name": "test.example.com",
                    "common_name": "test.example.com",
                    "alternative_names": {
                        "dns": ["www.example.com"],
                        "ip": ["192.168.1.10"],
                    },
                    "export": {
                        "cert": "/tmp/test/cert.pem",
                        "chain": "/tmp/test/chain.pem",
                    },
                    "deploy": {
                        "command": "systemctl reload nginx",
                    },
                    "validity": {
                        "days": 365,
                    },
                    "key_algorithm": "RSA2048",
                }
            ]
        }
        yaml.dump(valid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "hosts_config_schema.yaml")
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_hosts_config_valid_rsa4096() -> None:
    """Test validating a valid hosts configuration (RSA4096)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        valid_config = {
            "hosts": [
                {
                    "name": "test.example.com",
                    "common_name": "test.example.com",
                    "alternative_names": {
                        "dns": ["www.example.com"],
                        "ip": ["192.168.1.10"],
                    },
                    "export": {
                        "cert": "/tmp/test/cert.pem",
                        "chain": "/tmp/test/chain.pem",
                    },
                    "deploy": {
                        "command": "systemctl reload nginx",
                    },
                    "validity": {
                        "days": 365,
                    },
                    "key_algorithm": "RSA4096",
                }
            ]
        }
        yaml.dump(valid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "hosts_config_schema.yaml")
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_hosts_config_invalid1() -> None:
    """Test validating an invalid hosts configuration (common name, algo)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "hosts": [
                {
                    "name": "test.example.com",
                    # Missing required field
                    # "common_name": "test.example.com",
                    "alternative_names": {
                        "dns": ["www.example.com"],
                        "ip": ["192.168.1.10"],
                    },
                    "validity": {
                        "days": 365,
                    },
                    "key_algorithm": "INVALID",  # Invalid algorithm
                }
            ]
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "hosts_config_schema.yaml")
        assert not valid
        assert errors


def test_validate_hosts_config_invalid2() -> None:
    """Test validating a valid hosts configuration (invalid key algorithm)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "hosts": [
                {
                    "name": "test.example.com",
                    "common_name": "test.example.com",
                    "alternative_names": {
                        "dns": ["www.example.com"],
                        "ip": ["192.168.1.10"],
                    },
                    "export": {
                        "cert": "/tmp/test/cert.pem",
                        "chain": "/tmp/test/chain.pem",
                    },
                    "deploy": {
                        "command": "systemctl reload nginx",
                    },
                    "validity": {
                        "days": 365,
                    },
                    "key_algorithm": "RSA2047",  # Invalid algorithm (not in enum)
                }
            ]
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        valid, errors = validate_config(Path(tmp_file.name), "hosts_config_schema.yaml")
        assert not valid
        assert errors


def test_default_config_ca_validates() -> None:
    """Test that the default CA config created by utils.create_default_config passes validation."""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Change to temp directory to avoid affecting real config
        original_cwd = Path.cwd()
        temp_path = Path(temp_dir)

        try:
            # Create config directory in the temp directory
            config_dir = temp_path / "config"
            config_dir.mkdir(exist_ok=True)

            # Temporarily change working directory
            os.chdir(temp_path)

            # Set environment variable for root directory
            os.environ["REACTOR_CA_ROOT"] = str(temp_path)

            # Create default configuration with explicit config
            config = Config.create(root_dir=str(temp_path))
            create_default_config(config)

            # Check the CA config file exists at the explicit path
            ca_config_path = config.ca_config_path
            print(f"Looking for CA config at: {ca_config_path}")
            assert ca_config_path.exists(), f"Default CA config was not created at {ca_config_path}"

            # Validate the CA config
            valid, errors = validate_config(ca_config_path, "ca_config_schema.yaml")
            if not valid:
                print(f"Validation errors: {errors}")
            assert valid, f"Default CA config does not validate against schema: {errors}"
            assert not errors

        finally:
            # Clean up and restore original working directory
            os.chdir(original_cwd)
            if "REACTOR_CA_ROOT" in os.environ:
                del os.environ["REACTOR_CA_ROOT"]


def test_default_config_hosts_validates() -> None:
    """Test that the default hosts config created by utils.create_default_config passes validation."""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Change to temp directory to avoid affecting real config
        original_cwd = Path.cwd()
        temp_path = Path(temp_dir)

        try:
            # Create config directory in the temp directory
            config_dir = temp_path / "config"
            config_dir.mkdir(exist_ok=True)

            # Temporarily change working directory
            os.chdir(temp_path)

            # Set environment variable for root directory
            os.environ["REACTOR_CA_ROOT"] = str(temp_path)

            # Create default configuration with explicit config
            config = Config.create(root_dir=str(temp_path))
            create_default_config(config)

            # Check the hosts config file exists at the explicit path
            hosts_config_path = config.hosts_config_path
            print(f"Looking for hosts config at: {hosts_config_path}")
            assert hosts_config_path.exists(), f"Default hosts config was not created at {hosts_config_path}"

            # Validate the hosts config
            valid, errors = validate_config(hosts_config_path, "hosts_config_schema.yaml")
            if not valid:
                print(f"Validation errors: {errors}")
            assert valid, f"Default hosts config does not validate against schema: {errors}"
            assert not errors

        finally:
            # Clean up and restore original working directory
            os.chdir(original_cwd)
            if "REACTOR_CA_ROOT" in os.environ:
                del os.environ["REACTOR_CA_ROOT"]
