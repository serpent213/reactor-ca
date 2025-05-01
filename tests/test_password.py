"""Password and encryption/decryption related tests."""

import os
import tempfile
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from reactor_ca.ca_operations import encrypt_key
from reactor_ca.cert_operations import import_host_key
from reactor_ca.utils import _password_cache_container


def test_import_host_key_with_different_password(monkeypatch):
    """Test that importing a host key with a different password than the CA fails."""
    # Create temporary directory and override the certs directory path
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock paths for CA and certs
        ca_dir = Path(temp_dir) / "store" / "ca"
        ca_dir.mkdir(parents=True, exist_ok=True)

        # Create a config directory
        config_dir = Path(temp_dir) / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        # Set current working directory to temp_dir so paths work as expected
        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            # Create a CA key with password1
            ca_password = "password1"
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            ca_key_path = ca_dir / "ca.key.enc"

            # Write the encrypted key
            with open(ca_key_path, "wb") as f:
                f.write(encrypt_key(ca_key, ca_password))

            # Create a temporary unencrypted host key file
            host_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            key_file = Path(temp_dir) / "temp_key.pem"
            with open(key_file, "wb") as f:
                f.write(
                    host_key.private_bytes(
                        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
                    )
                )

            # Create a hosts directory
            hosts_dir = Path(temp_dir) / "store" / "hosts"
            hosts_dir.mkdir(parents=True, exist_ok=True)

            # Create minimal config files
            ca_config = {
                "ca": {
                    "common_name": "Test CA",
                    "organization": "Test",
                    "organization_unit": "IT",
                    "country": "US",
                    "state": "CA",
                    "locality": "Test",
                    "email": "test@example.com",
                    "key": {"algorithm": "RSA", "size": 2048},
                    "password": {"min_length": 8},
                    "validity": {"days": 365},
                }
            }

            hosts_config = {
                "hosts": [
                    {
                        "name": "test_host",
                        "common_name": "test_host",
                        "alternative_names": {"dns": ["test_host"]},
                        "validity": {"days": 365},
                        "key": {"algorithm": "RSA", "size": 2048},
                    }
                ]
            }

            with open(config_dir / "ca.yaml", "w") as f:
                yaml.dump(ca_config, f)

            with open(config_dir / "hosts.yaml", "w") as f:
                yaml.dump(hosts_config, f)

            # Mock the confirmation prompt to always return True
            def mock_confirm(*args, **kwargs):
                return True

            monkeypatch.setattr("click.confirm", mock_confirm)

            # Try to import the key with a different password (should fail)
            different_password = "password2"

            # Directly pass the password to avoid prompting
            result = import_host_key("test_host", str(key_file), different_password)

            # The function should return False on failure, not raise an exception
            assert result is False

        finally:
            # Restore working directory and clear password cache
            os.chdir(original_dir)
            _password_cache_container[0] = None
