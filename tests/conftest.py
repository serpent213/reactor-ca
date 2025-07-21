"""Pytest configuration and shared fixtures for ReactorCA tests."""

import shlex
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner
from ruamel.yaml import YAML

from reactor_ca.cli import cli

# A strong, consistent password for all tests
TEST_PASSWORD = "super-secret-password-for-testing-123"


def openssl_run(args, cwd, check=True, stdin_data=None):
    """Run an openssl command and return the result."""
    cmd = ["openssl"] + shlex.split(args)
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check, input=stdin_data)
    return result


class CAWorkspace:
    """A helper class to manage a test environment for ReactorCA."""

    def __init__(self, tmp_path: Path, runner: CliRunner):
        self.root = tmp_path
        self.runner = runner
        self.config_dir = self.root / "config"
        self.store_dir = self.root / "store"
        self.yaml = YAML()
        self.yaml.preserve_quotes = True

        # Run config init to set up the directory structure
        result = self.run(["config", "init"])
        assert result.exit_code == 0
        assert "Configuration files initialized successfully" in result.output

    def run(self, args, password_input=None, env=None):
        """Invoke the ReactorCA CLI with common options."""
        base_args = ["--root", str(self.root)] + args
        return self.runner.invoke(cli, base_args, input=password_input, env=env)

    def get_ca_config(self):
        """Read the ca.yaml configuration file."""
        with open(self.config_dir / "ca.yaml") as f:
            return self.yaml.load(f)

    def set_ca_config(self, config_data):
        """Write to the ca.yaml configuration file."""
        with open(self.config_dir / "ca.yaml", "w") as f:
            self.yaml.dump(config_data, f)

    def get_hosts_config(self):
        """Read the hosts.yaml configuration file."""
        with open(self.config_dir / "hosts.yaml") as f:
            return self.yaml.load(f)

    def set_hosts_config(self, config_data):
        """Write to the hosts.yaml configuration file."""
        with open(self.config_dir / "hosts.yaml", "w") as f:
            self.yaml.dump(config_data, f)

    def create_ca(self, password=TEST_PASSWORD):
        """Helper to run 'ca create'."""
        result = self.run(["ca", "create"], password_input=f"{password}\n{password}\n")
        assert result.exit_code == 0, result.output
        assert "CA created successfully" in result.output
        return result

    def issue_host(self, hostname, password=TEST_PASSWORD):
        """Helper to run 'host issue <hostname>'."""
        result = self.run(["host", "issue", hostname], password_input=f"{password}\n")
        assert result.exit_code == 0, result.output
        assert f"Certificate created successfully for {hostname}" in result.output
        return result


@pytest.fixture
def runner() -> CliRunner:
    """Provides a Click CliRunner instance."""
    return CliRunner()


@pytest.fixture
def workspace(tmp_path: Path, runner: CliRunner) -> CAWorkspace:
    """
    Provides a fully initialized ReactorCA workspace in a temporary directory.
    This runs `ca config init` and returns a helper class for easy interaction.
    """
    return CAWorkspace(tmp_path, runner)


@pytest.fixture
def populated_workspace(workspace: CAWorkspace) -> CAWorkspace:
    """
    Provides a workspace with a CA and one host certificate ('server1') already issued.
    """
    # Create the CA
    workspace.create_ca()

    # Configure a host
    hosts_config = {
        "hosts": {
            "server1": {
                "common_name": "server1.homelab.local",
                "alternative_names": {
                    "dns": ["server1-alt.homelab.local"],
                    "ip": ["192.168.1.100", "fe80::1"],
                },
                "key_algorithm": "ECP256",
            }
        }
    }
    workspace.set_hosts_config(hosts_config)

    # Issue the host certificate
    workspace.issue_host("server1")

    return workspace
