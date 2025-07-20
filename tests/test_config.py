"""Tests for the configuration and validation."""

import os
import tempfile
from pathlib import Path

import yaml

from reactor_ca.config import init, create, validate, _validate_yaml
from reactor_ca.models import CAConfig, HostConfig, AlternativeNames, ValidityConfig, PasswordConfig
from reactor_ca.result import Success


def test_validate_ca_config_valid() -> None:
    """Test validating a valid CA configuration using the config._validate_yaml function."""
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

        # Use _validate_yaml with the test file
        validation_result = _validate_yaml(Path(tmp_file.name), "ca")
        assert isinstance(validation_result, Success)


def test_validate_ca_config_invalid() -> None:
    """Test validating an invalid CA configuration."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "ca": {
                "common_name": "Test CA",
                "organization": "Test Org",
                "organization_unit": "IT",
                "country": "US",
                "state": "Test State",
                "locality": "Test City",
                "email": "test@example.com",
                "key_algorithm": "RSA4096",
                # Invalid validity - specifying both days and years
                "validity": {
                    "days": 365,
                    "years": 10,
                },
                "password": {
                    "min_length": 12,
                },
            }
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        validation_result = _validate_yaml(Path(tmp_file.name), "ca")
        assert not isinstance(validation_result, Success)


def test_validate_hosts_config_valid_rsa2048() -> None:
    """Test validating a valid hosts configuration (RSA2048)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        valid_config = {
            "hosts": {
                "test.example.com": {
                    "host_id": "test.example.com",
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
            }
        }
        yaml.dump(valid_config, tmp_file)
        tmp_file.flush()

        validation_result = _validate_yaml(Path(tmp_file.name), "hosts")
        assert isinstance(validation_result, Success)


def test_validate_hosts_config_valid_rsa4096() -> None:
    """Test validating a valid hosts configuration (RSA4096)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        valid_config = {
            "hosts": {
                "test.example.com": {
                    "host_id": "test.example.com",
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
            }
        }
        yaml.dump(valid_config, tmp_file)
        tmp_file.flush()

        validation_result = _validate_yaml(Path(tmp_file.name), "hosts")
        assert isinstance(validation_result, Success)


def test_validate_hosts_config_invalid1() -> None:
    """Test validating an invalid hosts configuration (common name, algo)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "hosts": {
                "test.example.com": {
                    "host_id": "test.example.com",
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
            }
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        validation_result = _validate_yaml(Path(tmp_file.name), "hosts")
        assert not isinstance(validation_result, Success)


def test_validate_hosts_config_invalid2() -> None:
    """Test validating a valid hosts configuration (invalid key algorithm)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="locale") as tmp_file:
        invalid_config = {
            "hosts": {
                "test.example.com": {
                    "host_id": "test.example.com",
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
            }
        }
        yaml.dump(invalid_config, tmp_file)
        tmp_file.flush()

        validation_result = _validate_yaml(Path(tmp_file.name), "hosts")
        assert not isinstance(validation_result, Success)


def test_default_config_create_and_validate() -> None:
    """Test that creating and validating default config works."""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Use the temp directory
        temp_path = Path(temp_dir)

        # Create config
        config_result = create(temp_path / "config")
        assert isinstance(config_result, Success)

        # Validate config
        validation_result = validate(temp_path / "config")
        assert isinstance(validation_result, Success)


def test_models_validity_config() -> None:
    """Test the ValidityConfig model."""
    # Test with days
    validity_days = ValidityConfig(days=365)
    days_result = validity_days.to_days()
    assert isinstance(days_result, Success)
    assert days_result.unwrap() == 365

    # Test with years
    validity_years = ValidityConfig(years=1)
    years_result = validity_years.to_days()
    assert isinstance(years_result, Success)
    assert years_result.unwrap() == 365

    # Test model validation - shouldn't be able to set both
    try:
        ValidityConfig(days=365, years=1)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_alternative_names() -> None:
    """Test the AlternativeNames model."""
    # Valid DNS
    alt_names = AlternativeNames(dns=["valid.example.com"])
    assert not alt_names.is_empty()

    # Invalid DNS
    try:
        AlternativeNames(dns=["invalid..example.com"])
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    # Valid IP
    alt_names = AlternativeNames(ip=["192.168.1.1"])
    assert not alt_names.is_empty()

    # Invalid IP
    try:
        AlternativeNames(ip=["999.999.999.999"])
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
