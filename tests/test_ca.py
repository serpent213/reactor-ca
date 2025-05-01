"""Tests for CA operations in ReactorCA."""

import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from reactor_ca.main import cli


def test_cli_version() -> None:
    """Test CLI version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "version" in result.output.lower()


def test_cli_help() -> None:
    """Test CLI help command."""
    runner = CliRunner()
    help_result = runner.invoke(cli, ["--help"])
    assert help_result.exit_code == 0

    # Verify command groups are included in help
    command_groups = ["config", "ca", "host", "util"]
    for cmd in command_groups:
        assert cmd in help_result.output


def test_ca_info() -> None:
    """Test 'ca info' command after initializing a CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)

            # Create sample config file with env var for password
            config_content = """
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

            with open("config/ca.yaml", "w") as f:
                f.write(config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # Create the CA first using the new 'issue' command
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\ntestpassword\n")
            assert result.exit_code == 0
            assert Path("store/ca/ca.crt").exists()
            assert Path("store/ca/ca.key.enc").exists()

            # Now test the ca info command
            result = runner.invoke(cli, ["ca", "info"])
            assert result.exit_code == 0

            # Check for expected information in output
            assert "CA Certificate Information" in result.output
            assert "Subject: Test CA" in result.output
            assert "Organization: Test Org" in result.output
            assert "Organizational Unit: IT" in result.output
            assert "Country: US" in result.output
            assert "State/Province: Test State" in result.output
            assert "Locality: Test City" in result.output
            assert "Email: test@example.com" in result.output
            assert "Days Remaining" in result.output
            assert "Fingerprint" in result.output

            # Test JSON output
            result = runner.invoke(cli, ["ca", "info", "--json"])
            assert result.exit_code == 0
            assert "subject" in result.output
            assert "common_name" in result.output
            assert "serial" in result.output
            assert "fingerprint" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)


def test_ca_issue_new() -> None:
    """Test 'ca issue' command to create a new CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)

            # Create sample config file with env var for password
            config_content = """
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

            with open("config/ca.yaml", "w") as f:
                f.write(config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # Run initialization with new 'issue' command
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\ntestpassword\n")

            print(f"Exit code: {result.exit_code}")
            print(f"Output: {result.output}")
            print(f"Exception: {result.exception}")

            assert result.exit_code == 0
            assert Path("store/ca/ca.crt").exists()
            assert Path("store/ca/ca.key.enc").exists()
            assert Path("store/inventory.yaml").exists()
            assert "CA created successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)


def test_ca_issue_renew() -> None:
    """Test 'ca issue' command to renew an existing CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)

            # Create sample config file with env var for password
            config_content = """
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

            with open("config/ca.yaml", "w") as f:
                f.write(config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # First create a CA
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\ntestpassword\n")
            assert result.exit_code == 0

            # Get the creation date of the certificate
            original_mtime = Path("store/ca/ca.crt").stat().st_mtime

            # Now renew the CA
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\n")
            assert result.exit_code == 0

            # Verify the certificate was updated
            new_mtime = Path("store/ca/ca.crt").stat().st_mtime
            assert new_mtime > original_mtime
            assert "CA certificate renewed successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)


def test_ca_rekey() -> None:
    """Test 'ca rekey' command to rekey an existing CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("store/ca").mkdir(parents=True, exist_ok=True)

            # Create sample config file with env var for password
            config_content = """
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

            with open("config/ca.yaml", "w") as f:
                f.write(config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # First create a CA
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "issue"], input="testpassword\ntestpassword\n")
            assert result.exit_code == 0

            # Get the original certificate and key modification times
            original_cert_mtime = Path("store/ca/ca.crt").stat().st_mtime
            original_key_mtime = Path("store/ca/ca.key.enc").stat().st_mtime

            # Now rekey the CA using the dedicated 'rekey' command
            result = runner.invoke(cli, ["ca", "rekey"], input="testpassword\n")
            assert result.exit_code == 0

            # Verify both the certificate and key were updated
            new_cert_mtime = Path("store/ca/ca.crt").stat().st_mtime
            new_key_mtime = Path("store/ca/ca.key.enc").stat().st_mtime

            assert new_cert_mtime > original_cert_mtime
            assert new_key_mtime > original_key_mtime
            assert "CA rekeyed successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)
