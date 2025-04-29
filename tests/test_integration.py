"""Integration tests for ReactorCA workflows.

These tests simulate typical workflows like setting up a new CA and issuing certificates.
"""

import json
import os
import shutil
import subprocess
import tempfile

import pytest
import yaml
from click.testing import CliRunner
from cryptography import x509
from cryptography.x509.oid import NameOID

from reactor_ca.main import cli


def run_command(command):
    """Run a shell command and return its output."""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,  # Add timeout to prevent hanging
    )
    return result


def check_openssl_available():
    """Check if openssl is available in the system."""
    try:
        result = run_command("which openssl")
        return result.returncode == 0
    except Exception:
        return False


# Skip tests that require openssl if it's not available
requires_openssl = pytest.mark.skipif(not check_openssl_available(), reason="OpenSSL not available")


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    original_dir = os.getcwd()
    os.chdir(temp_dir)

    # Create necessary directories
    os.makedirs("config", exist_ok=True)
    os.makedirs("certs", exist_ok=True)

    yield temp_dir

    # Clean up
    os.chdir(original_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def create_test_configs(temp_dir):
    """Create test configurations optimized for fast test execution."""
    # CA config with minimal parameters for quick testing
    ca_config = {
        "ca": {
            "common_name": "Test CA",
            "organization": "Test Org",
            "organization_unit": "IT",
            "country": "US",
            "state": "Test State",
            "locality": "Test City",
            "email": "test@example.com",
            "key": {
                "algorithm": "RSA",
                "size": 2048,  # Use smaller key size for faster tests
            },
            "validity": {
                "days": 30,  # Short validity period for testing
            },
            "password": {
                "min_length": 8,
                "env_var": "TEST_CA_PASSWORD",  # Use environment variable for password
            },
        }
    }

    # Host config
    hosts_config = {
        "hosts": [
            {
                "name": "testserver.local",
                "common_name": "testserver.local",
                # Test partial override of certificate metadata fields
                # Only override organization_unit and email, inherit the rest from CA
                "organization_unit": "Test Override Unit",
                "email": "override@example.com",
                "alternative_names": {
                    "dns": ["www.testserver.local"],
                    "ip": ["192.168.1.10"],
                },
                "export": {
                    "cert": f"{temp_dir}/exported/testserver.crt",
                    "chain": f"{temp_dir}/exported/testserver-chain.crt",
                },
                "deploy": {
                    "command": "echo 'Certificate deployed'",
                },
                "validity": {
                    "days": 30,  # Short validity period for testing
                },
                "key": {
                    "algorithm": "RSA",
                    "size": 2048,
                },
            }
        ]
    }

    # Create export directory
    os.makedirs(f"{temp_dir}/exported", exist_ok=True)

    # Write CA config
    ca_config_path = os.path.join("config", "ca_config.yaml")
    with open(ca_config_path, "w") as f:
        yaml.dump(ca_config, f)

    # Write hosts config
    hosts_config_path = os.path.join("config", "hosts.yaml")
    with open(hosts_config_path, "w") as f:
        yaml.dump(hosts_config, f)

    # Set environment variable for test password
    os.environ["TEST_CA_PASSWORD"] = "testpassword"

    return {"ca_config": ca_config_path, "hosts_config": hosts_config_path}


class TestReactorCAIntegration:
    """Integration tests for ReactorCA."""

    def test_config_init(self, temp_dir) -> None:
        """Test initializing configuration."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init"])

        assert result.exit_code == 0
        assert os.path.exists(os.path.join("config", "ca_config.yaml"))
        assert os.path.exists(os.path.join("config", "hosts.yaml"))

    def test_ca_create(self, temp_dir, create_test_configs) -> None:
        """Test creating a new CA."""
        # Create CA (configs are already created by fixture)
        runner = CliRunner()
        result = runner.invoke(cli, ["ca", "create"])

        assert result.exit_code == 0
        assert os.path.exists(os.path.join("certs", "ca", "ca.crt"))
        assert os.path.exists(os.path.join("certs", "ca", "ca.key.enc"))

        # Check CA information
        info_result = runner.invoke(cli, ["ca", "info", "--json"])
        assert info_result.exit_code == 0

        # Parse JSON output
        ca_info = json.loads(info_result.output)
        assert ca_info["subject"]["common_name"] == "Test CA"
        assert ca_info["subject"]["organization"] == "Test Org"
        assert ca_info["days_remaining"] > 0

    def test_basic_workflow(self, temp_dir, create_test_configs) -> None:
        """Test a basic workflow with CA creation and certificate issuance."""
        runner = CliRunner()

        # Create CA
        ca_result = runner.invoke(cli, ["ca", "create"])
        assert ca_result.exit_code == 0

        # Issue certificate for the test host
        cert_result = runner.invoke(cli, ["host", "issue", "testserver.local"])
        assert cert_result.exit_code == 0

        # Verify certificate was created
        assert os.path.exists(os.path.join("certs", "hosts", "testserver.local", "cert.crt"))
        assert os.path.exists(os.path.join("certs", "hosts", "testserver.local", "cert.key.enc"))

        # Verify export was successful
        assert os.path.exists(os.path.join(temp_dir, "exported", "testserver.crt"))
        assert os.path.exists(os.path.join(temp_dir, "exported", "testserver-chain.crt"))

        # List certificates
        list_result = runner.invoke(cli, ["host", "list", "--json"])
        assert list_result.exit_code == 0

        # Parse JSON output
        certs_info = json.loads(list_result.output)
        assert len(certs_info["hosts"]) == 1
        assert certs_info["hosts"][0]["name"] == "testserver.local"
        assert certs_info["hosts"][0]["days_remaining"] > 0

    @requires_openssl
    def test_openssl_verification(self, temp_dir, create_test_configs) -> None:
        """Test certificate verification using OpenSSL."""
        runner = CliRunner()

        # Create CA
        ca_result = runner.invoke(cli, ["ca", "create"])
        assert ca_result.exit_code == 0

        # Issue certificate for the test host
        cert_result = runner.invoke(cli, ["host", "issue", "testserver.local"])
        assert cert_result.exit_code == 0

        # Get file paths
        ca_cert_path = os.path.join("certs", "ca", "ca.crt")
        host_cert_path = os.path.join(temp_dir, "exported", "testserver.crt")

        # Verify certificate with OpenSSL

        # Verify CA certificate
        ca_verify_result = run_command(f"openssl x509 -in {ca_cert_path} -text -noout")
        assert ca_verify_result.returncode == 0
        assert "CA:TRUE" in ca_verify_result.stdout

        # Verify host certificate
        host_verify_result = run_command(f"openssl x509 -in {host_cert_path} -text -noout")
        assert host_verify_result.returncode == 0
        assert "testserver.local" in host_verify_result.stdout

        # Verify certificate chain
        chain_verify_result = run_command(f"openssl verify -CAfile {ca_cert_path} {host_cert_path}")
        assert chain_verify_result.returncode == 0
        assert "OK" in chain_verify_result.stdout

        # Verify SANs in the certificate
        sans_verify_result = run_command(f"openssl x509 -in {host_cert_path} -text -noout")
        assert sans_verify_result.returncode == 0
        assert "DNS:www.testserver.local" in sans_verify_result.stdout
        assert "IP Address:192.168.1.10" in sans_verify_result.stdout

        # Verify overridden and inherited certificate metadata fields are used correctly
        subject_verify_result = run_command(f"openssl x509 -in {host_cert_path} -noout -subject")
        assert subject_verify_result.returncode == 0

        # Print the actual output for debugging
        print(f"Subject output: {subject_verify_result.stdout}")

        # These fields should be inherited from CA
        assert "O=Test Org" in subject_verify_result.stdout
        assert "C=US" in subject_verify_result.stdout
        assert "ST=Test State" in subject_verify_result.stdout
        assert "L=Test City" in subject_verify_result.stdout

        # These fields should be overridden by host config
        assert "OU=Test Override Unit" in subject_verify_result.stdout
        assert "emailAddress=override@example.com" in subject_verify_result.stdout

    def test_renew_and_rekey(self, temp_dir, create_test_configs) -> None:
        """Test renewing and rekeying certificates."""
        runner = CliRunner()

        # Create CA and issue certificate
        runner.invoke(cli, ["ca", "create"])
        runner.invoke(cli, ["host", "issue", "testserver.local"])

        # Get initial certificate data
        ca_cert_path = os.path.join("certs", "ca", "ca.crt")
        host_cert_path = os.path.join("certs", "hosts", "testserver.local", "cert.crt")

        with open(ca_cert_path, "rb") as f:
            initial_ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(host_cert_path, "rb") as f:
            initial_host_cert = x509.load_pem_x509_certificate(f.read())

        # Renew CA certificate
        runner.invoke(cli, ["ca", "renew"])

        # Rekey host certificate
        runner.invoke(cli, ["host", "rekey", "testserver.local"])

        # Load renewed certificates
        with open(ca_cert_path, "rb") as f:
            renewed_ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(host_cert_path, "rb") as f:
            rekeyed_host_cert = x509.load_pem_x509_certificate(f.read())

        # Verify changed serials
        assert initial_ca_cert.serial_number != renewed_ca_cert.serial_number
        assert initial_host_cert.serial_number != rekeyed_host_cert.serial_number

        # Verify unchanged CNs
        ca_cn = renewed_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        host_cn = rekeyed_host_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        assert ca_cn == "Test CA"
        assert host_cn == "testserver.local"


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
