"""Tests for the ReactorCA tool."""

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
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0

    # Verify command groups are included in help
    command_groups = ["config", "ca", "host", "util"]
    for cmd in command_groups:
        assert cmd in result.output


def test_init_ca() -> None:
    """Test initializing a CA using environment variable for password."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("certs/ca").mkdir(parents=True, exist_ok=True)

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
              key:
                algorithm: "RSA"
                size: 2048
              validity:
                days: 365
              password:
                min_length: 8
                env_var: "TEST_CA_PASSWORD"
            """

            with open("config/ca_config.yaml", "w") as f:
                f.write(config_content)

            # Set environment variable for password with at least 8 characters
            os.environ["TEST_CA_PASSWORD"] = "testpassword"

            # Run initialization
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "create"])

            print(f"Exit code: {result.exit_code}")
            print(f"Output: {result.output}")
            print(f"Exception: {result.exception}")

            assert result.exit_code == 0
            assert Path("certs/ca/ca.crt").exists()
            assert Path("certs/ca/ca.key.enc").exists()
            assert Path("inventory.yaml").exists()

        finally:
            # Clean up environment variable
            if "TEST_CA_PASSWORD" in os.environ:
                del os.environ["TEST_CA_PASSWORD"]

            # Change back to original directory
            os.chdir(original_dir)
