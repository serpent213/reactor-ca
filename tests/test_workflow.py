"""Test the primary E2E workflow for ReactorCA."""

import json

from tests.conftest import TEST_PASSWORD, openssl_run


def test_full_e2e_workflow(workspace):
    """
    Tests the main workflow: init -> create CA -> configure host -> issue host cert -> verify.
    This acts as a smoke test for the entire application.
    """
    # 1. Create a CA
    result = workspace.create_ca()
    assert result.exit_code == 0
    assert "CA created successfully" in result.output

    ca_cert_path = workspace.store_dir / "ca" / "ca.crt"
    ca_key_path = workspace.store_dir / "ca" / "ca.key.enc"
    assert ca_cert_path.exists()
    assert ca_key_path.exists()

    # 2. Validate CA certificate and key with openssl
    # Check certificate details (self-signed, subject)
    ca_cert_info = openssl_run(f"x509 -in {ca_cert_path.name} -noout -text", cwd=ca_cert_path.parent)
    assert "Issuer: CN = Reactor CA" in ca_cert_info.stdout
    assert "Subject: CN = Reactor CA" in ca_cert_info.stdout
    assert "CA:TRUE" in ca_cert_info.stdout

    # Check that the key is encrypted and valid
    openssl_run(f"rsa -in {ca_key_path.name} -noout -check -passin pass:{TEST_PASSWORD}", cwd=ca_key_path.parent)

    # 3. Configure a host
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

    # 4. Issue a certificate for the host
    result = workspace.issue_host("server1")
    assert f"Certificate created successfully for [bold]server1[/bold]" in result.output

    host_cert_path = workspace.store_dir / "hosts" / "server1" / "cert.crt"
    host_key_path = workspace.store_dir / "hosts" / "server1" / "cert.key.enc"
    assert host_cert_path.exists()
    assert host_key_path.exists()

    # 5. Validate the host certificate with openssl
    # Verify it's signed by our CA
    openssl_run(f"verify -CAfile {ca_cert_path} {host_cert_path}", cwd=workspace.root)

    # Check certificate details (issuer, subject, SANs)
    host_cert_info = openssl_run(f"x509 -in {host_cert_path} -noout -text", cwd=workspace.root)
    assert "Issuer: CN = Reactor CA" in host_cert_info.stdout
    assert "Subject: CN = server1.homelab.local" in host_cert_info.stdout
    assert "DNS:server1-alt.homelab.local" in host_cert_info.stdout
    assert "IP Address:192.168.1.100" in host_cert_info.stdout
    assert "IP Address:fe80::1" in host_cert_info.stdout

    # Check the host key is valid and encrypted
    openssl_run(f"ec -in {host_key_path} -noout -check -passin pass:{TEST_PASSWORD}", cwd=workspace.root)

    # 6. Test list and info commands
    list_result = workspace.run(["host", "list"])
    assert "server1" in list_result.output
    assert "server1.homelab.local" not in list_result.output  # Should show host ID

    ca_info_result = workspace.run(["ca", "info", "--json"])
    ca_info_data = json.loads(ca_info_result.stdout)
    assert ca_info_data["subject"]["common_name"] == "Reactor CA"
    assert ca_info_data["key_present"] is True
