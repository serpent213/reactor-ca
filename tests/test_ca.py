"""Tests for CA operations in ReactorCA."""

import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from reactor_ca.main import cli
from tests.helpers import assert_cert_paths, setup_test_env


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
        # Setup test environment with proper paths
        store = setup_test_env(tmpdir)

        # Create directories needed for tests
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir(exist_ok=True)

        # Create sample config file directly to match expected format
        config_content = """
ca:
  common_name: Test CA
  organization: Test Org
  organization_unit: IT
  country: US
  state: Test State
  locality: Test City
  email: test@example.com
  key_algorithm: RSA2048
  validity:
    days: 365
  password:
    min_length: 8
    env_var: TEST_CA_PASSWORD
"""

        # Write the config file directly
        with open(store.config.ca_config_path, "w", encoding="locale") as f:
            f.write(config_content)

        # Set environment variable for password
        os.environ["TEST_CA_PASSWORD"] = "testpassword"

        try:
            # Create the CA using the 'issue' command with explicit paths
            runner = CliRunner()
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "issue"], input="testpassword\ntestpassword\n", catch_exceptions=False
            )

            # Always print debug output to see what's happening
            print(f"Debug - CLI exit code: {result.exit_code}")
            print(f"Debug - CLI output: {result.output}")
            if result.exception:
                print(f"Debug - CLI exception: {result.exception}")

            assert result.exit_code == 0

            # Verify certificate paths
            assert_cert_paths(store)

            # Test the ca info command with explicit paths
            result = runner.invoke(cli, ["--root", tmpdir, "ca", "info"])

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
            result = runner.invoke(cli, ["--root", tmpdir, "ca", "info", "--json"])

            assert result.exit_code == 0
            assert "subject" in result.output
            assert "common_name" in result.output
            assert "serial" in result.output
            assert "fingerprint" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]


def test_ca_issue_new() -> None:
    """Test 'ca issue' command to create a new CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup test environment with proper paths
        store = setup_test_env(tmpdir)

        # Create directories needed for tests
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir(exist_ok=True)

        # Create sample config file directly to match expected format
        config_content = """
ca:
  common_name: Test CA
  organization: Test Org
  organization_unit: IT
  country: US
  state: Test State
  locality: Test City
  email: test@example.com
  key_algorithm: RSA2048
  validity:
    days: 365
  password:
    min_length: 8
    env_var: TEST_CA_PASSWORD
"""

        # Write the config file directly
        with open(store.config.ca_config_path, "w", encoding="locale") as f:
            f.write(config_content)

        # Set environment variable for password
        os.environ["TEST_CA_PASSWORD"] = "testpassword"

        try:
            # Run initialization with 'issue' command and explicit paths
            runner = CliRunner()
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "issue"], input="testpassword\ntestpassword\n", catch_exceptions=False
            )

            # Always print debug output to see what's happening
            print(f"Debug - CLI exit code: {result.exit_code}")
            print(f"Debug - CLI output: {result.output}")
            if result.exception:
                print(f"Debug - CLI exception: {result.exception}")

            assert result.exit_code == 0

            # Verify certificate paths
            assert_cert_paths(store)

            # Also check inventory
            assert store.config.inventory_path.exists()
            assert "CA created successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]


def test_ca_issue_renew() -> None:
    """Test 'ca issue' command to renew an existing CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup test environment with proper paths
        store = setup_test_env(tmpdir)

        # Create directories needed for tests
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir(exist_ok=True)

        # Create sample config file directly to match expected format
        config_content = """
ca:
  common_name: Test CA
  organization: Test Org
  organization_unit: IT
  country: US
  state: Test State
  locality: Test City
  email: test@example.com
  key_algorithm: RSA2048
  validity:
    days: 365
  password:
    min_length: 8
    env_var: TEST_CA_PASSWORD
"""

        # Write the config file directly
        with open(store.config.ca_config_path, "w", encoding="locale") as f:
            f.write(config_content)

        # Set environment variable for password
        os.environ["TEST_CA_PASSWORD"] = "testpassword"

        try:
            # First create a CA with explicit paths
            runner = CliRunner()
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "issue"], input="testpassword\ntestpassword\n", catch_exceptions=False
            )
            assert result.exit_code == 0

            # Verify the certificate exists
            assert_cert_paths(store)

            # Get the creation date of the certificate
            ca_cert_path = store.get_ca_cert_path()
            original_mtime = ca_cert_path.stat().st_mtime

            # Now renew the CA with explicit paths
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "issue"], input="testpassword\n", catch_exceptions=False
            )

            # Debug output if it fails
            if result.exit_code != 0:
                print(f"Debug - CLI output: {result.output}")
                print(f"Debug - CLI exception: {result.exception}")

            assert result.exit_code == 0

            # Verify the certificate was updated
            new_mtime = ca_cert_path.stat().st_mtime
            assert new_mtime > original_mtime
            assert "CA certificate renewed successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]


def test_ca_rekey() -> None:
    """Test 'ca rekey' command to rekey an existing CA."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup test environment with proper paths
        store = setup_test_env(tmpdir)

        # Create directories needed for tests
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir(exist_ok=True)

        # Create sample config file directly to match expected format
        config_content = """
ca:
  common_name: Test CA
  organization: Test Org
  organization_unit: IT
  country: US
  state: Test State
  locality: Test City
  email: test@example.com
  key_algorithm: RSA2048
  validity:
    days: 365
  password:
    min_length: 8
    env_var: TEST_CA_PASSWORD
"""

        # Write the config file directly
        with open(store.config.ca_config_path, "w", encoding="locale") as f:
            f.write(config_content)

        # Set environment variable for password
        os.environ["TEST_CA_PASSWORD"] = "testpassword"

        try:
            # First create a CA with explicit paths
            runner = CliRunner()
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "issue"], input="testpassword\ntestpassword\n", catch_exceptions=False
            )
            assert result.exit_code == 0

            # Verify certificate paths
            assert_cert_paths(store)

            # Get paths from the store
            ca_cert_path = store.get_ca_cert_path()
            ca_key_path = store.get_ca_key_path()

            # Get the original certificate and key modification times
            original_cert_mtime = ca_cert_path.stat().st_mtime
            original_key_mtime = ca_key_path.stat().st_mtime

            # Now rekey the CA using the dedicated 'rekey' command with explicit paths
            result = runner.invoke(
                cli, ["--root", tmpdir, "ca", "rekey"], input="testpassword\n", catch_exceptions=False
            )

            # Debug output if it fails
            if result.exit_code != 0:
                print(f"Debug - CLI output: {result.output}")
                print(f"Debug - CLI exception: {result.exception}")

            assert result.exit_code == 0

            # Verify both the certificate and key were updated
            new_cert_mtime = ca_cert_path.stat().st_mtime
            new_key_mtime = ca_key_path.stat().st_mtime

            assert new_cert_mtime > original_cert_mtime
            assert new_key_mtime > original_key_mtime
            assert "CA rekeyed successfully" in result.output

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]
