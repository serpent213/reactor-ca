"""Tests for management commands like rekey, passwd, deploy, and clean."""

import json

from tests.conftest import TEST_PASSWORD, openssl_run


def test_ca_rekey(populated_workspace):
    """Test re-keying the Certificate Authority."""
    ws = populated_workspace
    ca_cert_path = ws.store_dir / "ca" / "ca.crt"
    ca_key_path = ws.store_dir / "ca" / "ca.key.enc"

    # Get original cert serial and key's public part
    original_serial = openssl_run(f"x509 -in {ca_cert_path} -noout -serial", cwd=ws.root).stdout
    original_pubkey = openssl_run(f"rsa -in {ca_key_path} -pubout -passin pass:{TEST_PASSWORD}", cwd=ws.root).stdout

    # Rekey the CA
    result = ws.run(["ca", "rekey"], password_input=f"{TEST_PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "CA rekeyed successfully" in result.output

    # Get new cert serial and key's public part
    new_serial = openssl_run(f"x509 -in {ca_cert_path} -noout -serial", cwd=ws.root).stdout
    new_pubkey = openssl_run(f"rsa -in {ca_key_path} -pubout -passin pass:{TEST_PASSWORD}", cwd=ws.root).stdout

    assert original_serial != new_serial
    assert original_pubkey != new_pubkey


def test_host_rekey(populated_workspace):
    """Test re-keying a host certificate."""
    ws = populated_workspace
    host_cert_path = ws.store_dir / "hosts" / "server1" / "cert.crt"
    host_key_path = ws.store_dir / "hosts" / "server1" / "cert.key.enc"

    original_serial = openssl_run(f"x509 -in {host_cert_path} -noout -serial", cwd=ws.root).stdout
    original_pubkey = openssl_run(f"ec -in {host_key_path} -pubout -passin pass:{TEST_PASSWORD}", cwd=ws.root).stdout

    # Rekey the host
    result = ws.run(["host", "rekey", "server1"], password_input=f"{TEST_PASSWORD}\n")
    assert result.exit_code == 0
    assert "Certificate and key rekeyed successfully" in result.output

    new_serial = openssl_run(f"x509 -in {host_cert_path} -noout -serial", cwd=ws.root).stdout
    new_pubkey = openssl_run(f"ec -in {host_key_path} -pubout -passin pass:{TEST_PASSWORD}", cwd=ws.root).stdout

    assert original_serial != new_serial
    assert original_pubkey != new_pubkey


def test_change_password(populated_workspace):
    """Test changing the master password for all keys."""
    ws = populated_workspace
    new_password = "a-completely-different-password-456"
    ca_key_path = ws.store_dir / "ca" / "ca.key.enc"
    host_key_path = ws.store_dir / "hosts" / "server1" / "cert.key.enc"

    # Change password
    password_input = f"{TEST_PASSWORD}\n{new_password}\n{new_password}\n"
    result = ws.run(["util", "passwd"], password_input=password_input)
    assert result.exit_code == 0
    assert "Password changed successfully for all keys" in result.output

    # Verify keys are now encrypted with the new password
    openssl_run(f"rsa -in {ca_key_path.name} -noout -check -passin pass:{new_password}", cwd=ca_key_path.parent)
    openssl_run(f"ec -in {host_key_path.name} -noout -check -passin pass:{new_password}", cwd=host_key_path.parent)

    # Verify old password no longer works (it will fail with a non-zero exit code)
    with pytest.raises(subprocess.CalledProcessError):
        openssl_run(f"rsa -in {ca_key_path.name} -noout -check -passin pass:{TEST_PASSWORD}", cwd=ca_key_path.parent)


def test_host_clean(populated_workspace):
    """Test cleaning up store directories for hosts no longer in config."""
    ws = populated_workspace
    server1_dir = ws.store_dir / "hosts" / "server1"
    assert server1_dir.is_dir()

    # Remove server1 from config
    hosts_config = ws.get_hosts_config()
    del hosts_config["hosts"]["server1"]
    ws.set_hosts_config(hosts_config)

    # Run clean
    result = ws.run(["host", "clean"])
    assert result.exit_code == 0
    assert "Removed host folder for [bold]server1[/bold]" in result.output

    assert not server1_dir.exists()


def test_host_deploy(populated_workspace):
    """Test the deployment command execution."""
    ws = populated_workspace
    deploy_flag_file = ws.root / "deployed.flag"
    deploy_output_file = ws.root / "deploy_output.txt"

    # Update host config with a deploy command
    hosts_config = ws.get_hosts_config()
    hosts_config["hosts"]["server1"]["deploy"] = {
        "command": f"sh -c 'touch {deploy_flag_file} && cat ${{private_key}} > {deploy_output_file}'"
    }
    ws.set_hosts_config(hosts_config)

    # Issue and deploy
    result = ws.run(["host", "issue", "server1", "--deploy"], password_input=f"{TEST_PASSWORD}\n")
    assert result.exit_code == 0
    assert "Deployment command executed successfully" in result.output

    # Verify deployment artifacts
    assert deploy_flag_file.exists()
    assert deploy_output_file.exists()
    # The output file should contain an unencrypted private key
    assert "BEGIN EC PRIVATE KEY" in deploy_output_file.read_text()


def test_list_json_output(populated_workspace):
    """Test the JSON output of 'host list'."""
    ws = populated_workspace
    result = ws.run(["host", "list", "--json"])
    assert result.exit_code == 0

    data = json.loads(result.stdout)
    assert "ca" in data
    assert "hosts" in data
    assert len(data["hosts"]) == 1
    assert data["hosts"][0]["host_id"] == "server1"
    assert isinstance(data["hosts"][0]["days_remaining"], int)
