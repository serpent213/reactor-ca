"""Tests for host operations in ReactorCA."""

import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from reactor_ca.main import cli


def test_host_issue_with_key_check() -> None:
    """Test 'host issue' command with key algorithm verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)

            # Create sample CA config
            ca_config_content = """
            ca:
              common_name: "Test CA"
              organization: "Test Org"
              organization_unit: "IT"
              country: "US"
              state: "Test State"
              locality: "Test City"
              email: "test@example.com"
              key_algorithm: "RSA2048"
              validity:
                days: 365
              password:
                min_length: 8
                env_var: "TEST_CA_PASSWORD"
            """

            # Create sample hosts config with a host
            hosts_config_content = """
            hosts:
              - name: "test.example.com"
                common_name: "test.example.com"
                key_algorithm: "RSA2048"
                validity:
                  days: 365
            """

            with open("config/ca.yaml", "w") as f:
                f.write(ca_config_content)

            with open("config/hosts.yaml", "w") as f:
                f.write(hosts_config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # Create the CA first
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\ntestpassword\n")
            assert result.exit_code == 0

            # Issue host certificate
            result = runner.invoke(cli, ["host", "issue", "test.example.com"], input="testpassword\ntestpassword\n")
            assert result.exit_code == 0
            assert Path("store/hosts/test.example.com/cert.crt").exists()
            assert Path("store/hosts/test.example.com/cert.key.enc").exists()

            # Get the original certificate modification time
            original_cert_mtime = Path("store/hosts/test.example.com/cert.crt").stat().st_mtime

            # Now renew the certificate
            result = runner.invoke(cli, ["host", "issue", "test.example.com"], input="testpassword\n")
            assert result.exit_code == 0

            # Verify certificate was updated
            new_cert_mtime = Path("store/hosts/test.example.com/cert.crt").stat().st_mtime
            assert new_cert_mtime > original_cert_mtime

            # Change the key algorithm in the hosts config to test the validation
            hosts_config_content = """
            hosts:
              - name: "test.example.com"
                common_name: "test.example.com"
                key_algorithm: "RSA4096"  # Changed from RSA2048
                validity:
                  days: 365
            """

            with open("config/hosts.yaml", "w") as f:
                f.write(hosts_config_content)

            # Try to renew the certificate - should fail due to key algorithm mismatch
            result = runner.invoke(cli, ["host", "issue", "test.example.com"], input="testpassword\n")
            assert "The existing key algorithm does not match the configuration" in result.output

            # Rekey should work with new algorithm
            result = runner.invoke(cli, ["host", "rekey", "test.example.com"], input="testpassword\n")
            assert result.exit_code == 0
            assert "rekeyed successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)


def test_host_clean() -> None:
    """Test 'host clean' command to remove obsolete host folders."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)
            Path("store/hosts").mkdir(parents=True, exist_ok=True)

            # Create host directories - some that will remain in config and some that will be removed
            host1_dir = Path("store/hosts/host1.example.com")
            host2_dir = Path("store/hosts/host2.example.com")
            host3_dir = Path("store/hosts/host3.example.com")

            host1_dir.mkdir(exist_ok=True)
            host2_dir.mkdir(exist_ok=True)
            host3_dir.mkdir(exist_ok=True)

            # Create dummy certificate files
            (host1_dir / "cert.crt").touch()
            (host1_dir / "cert.key.enc").touch()
            (host2_dir / "cert.crt").touch()
            (host2_dir / "cert.key.enc").touch()
            (host3_dir / "cert.crt").touch()
            (host3_dir / "cert.key.enc").touch()

            # Create sample CA config
            ca_config_content = """
            ca:
              common_name: "Test CA"
              organization: "Test Org"
              organization_unit: "IT"
              country: "US"
              state: "Test State"
              locality: "Test City"
              email: "test@example.com"
              key_algorithm: "RSA2048"
              validity:
                days: 365
              password:
                min_length: 8
                env_var: "TEST_CA_PASSWORD"
            """

            # Create sample hosts config with only host1 and host2
            hosts_config_content = """
            hosts:
              - name: "host1.example.com"
                common_name: "host1.example.com"
                key_algorithm: "RSA2048"
                validity:
                  days: 365
              - name: "host2.example.com"
                common_name: "host2.example.com"
                key_algorithm: "RSA2048"
                validity:
                  days: 365
            """

            with open("config/ca.yaml", "w") as f:
                f.write(ca_config_content)

            with open("config/hosts.yaml", "w") as f:
                f.write(hosts_config_content)

            # Create an inventory file
            inventory_content = """
            last_update: "2023-01-01T00:00:00.000000Z"
            ca: {}
            hosts:
              - name: "host1.example.com"
                serial: "1234"
                not_after: "2024-01-01T00:00:00.000000Z"
                fingerprint: "SHA256:1234"
                renewal_count: 1
              - name: "host2.example.com"
                serial: "5678"
                not_after: "2024-01-01T00:00:00.000000Z"
                fingerprint: "SHA256:5678"
                renewal_count: 1
              - name: "host3.example.com"
                serial: "9012"
                not_after: "2024-01-01T00:00:00.000000Z"
                fingerprint: "SHA256:9012"
                renewal_count: 1
            """

            with open("store/inventory.yaml", "w") as f:
                f.write(inventory_content)

            # Run the host clean command, confirming removal
            runner = CliRunner()
            result = runner.invoke(cli, ["host", "clean"], input="y\n")

            # Check that the command completed successfully
            assert result.exit_code == 0

            # Check that host3 was identified for removal
            assert "Remove host folder for host3.example.com?" in result.output

            # Check that host3 directory no longer exists
            assert not host3_dir.exists()

            # Check that host1 and host2 directories still exist
            assert host1_dir.exists()
            assert host2_dir.exists()

            # Check that inventory was updated
            assert "Updating inventory..." in result.output
            assert "✅ Inventory updated." in result.output

        finally:
            # Change back to original directory
            os.chdir(original_dir)
