"""Tests for the configuration validator."""

import tempfile

import yaml

from reactor_ca.config_validator import validate_ca_config, validate_hosts_config


def test_validate_ca_config_valid() -> None:
    """Test validating a valid CA configuration."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_ca_config(tmp_file.name)
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_ca_config_invalid() -> None:
    """Test validating an invalid CA configuration."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_ca_config(tmp_file.name)
        assert not valid
        assert errors


def test_validate_hosts_config_valid_rsa2048() -> None:
    """Test validating a valid hosts configuration (RSA2048)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_hosts_config(tmp_file.name)
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_hosts_config_valid_rsa4096() -> None:
    """Test validating a valid hosts configuration (RSA4096)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_hosts_config(tmp_file.name)
        if not valid:
            print(f"Validation errors: {errors}")
        assert valid
        assert not errors


def test_validate_hosts_config_invalid1() -> None:
    """Test validating an invalid hosts configuration (common name, algo)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_hosts_config(tmp_file.name)
        assert not valid
        assert errors


def test_validate_hosts_config_invalid2() -> None:
    """Test validating a valid hosts configuration (invalid key algorithm)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp_file:
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

        valid, errors = validate_hosts_config(tmp_file.name)
        assert not valid
        assert errors
