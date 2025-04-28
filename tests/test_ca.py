"""Tests for the ReactorCA tool."""

import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from reactor_ca.main import cli


def test_cli_version():
    """Test CLI version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "version" in result.output.lower()


def test_cli_help():
    """Test CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0

    # Verify command groups are included in help
    command_groups = ["config", "ca", "host", "util"]
    for cmd in command_groups:
        assert cmd in result.output


@pytest.mark.skip(reason="Requires user interaction for password")
def test_init_ca():
    """Test initializing a CA (requires user input for password)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temporary directory
        original_dir = os.getcwd()
        os.chdir(tmpdir)

        try:
            # Create necessary directories
            Path("config").mkdir(exist_ok=True)
            Path("certs/ca").mkdir(parents=True, exist_ok=True)

            # Create sample config file
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
              validity_days: 365
              password:
                min_length: 4
                storage: "session"
            """

            with open("config/ca_config.yaml", "w") as f:
                f.write(config_content)

            # Run initialization
            runner = CliRunner()
            result = runner.invoke(cli, ["ca", "create"], input="testpassword\n")

            assert result.exit_code == 0
            assert Path("certs/ca/ca.crt").exists()
            assert Path("certs/ca/ca.key.enc").exists()
            assert Path("inventory.yaml").exists()

        finally:
            # Change back to original directory
            os.chdir(original_dir)