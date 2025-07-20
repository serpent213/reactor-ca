"""Tests for import/export commands and CSR signing."""

from tests.conftest import TEST_PASSWORD, openssl_run


def test_ca_import(workspace):
    """Test importing an existing CA certificate and key."""
    # 1. Create an external CA with openssl
    external_ca_dir = workspace.root / "external_ca"
    external_ca_dir.mkdir()
    external_ca_key = external_ca_dir / "ca.key"
    external_ca_cert = external_ca_dir / "ca.crt"

    openssl_run(
        f"req -x509 -newkey rsa:2048 -keyout {external_ca_key.name} "
        f"-out {external_ca_cert.name} -sha256 -days 3650 -nodes "
        '-subj "/CN=External Test CA"',
        cwd=external_ca_dir,
    )

    # 2. Import the CA into ReactorCA
    result = workspace.run(
        ["ca", "import", "--cert", str(external_ca_cert), "--key", str(external_ca_key)],
        password_input=f"{TEST_PASSWORD}\n{TEST_PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output
    assert "CA imported successfully" in result.output

    # 3. Verify the imported CA in the store
    ca_cert_path = workspace.store_dir / "ca" / "ca.crt"
    ca_key_path = workspace.store_dir / "ca" / "ca.key.enc"
    assert ca_cert_path.exists()
    assert ca_key_path.exists()

    # Check the cert subject
    cert_info = openssl_run(f"x509 -in {ca_cert_path} -noout -subject", cwd=workspace.root)
    assert "CN = External Test CA" in cert_info.stdout

    # Check the key is now encrypted with the new password
    openssl_run(f"rsa -in {ca_key_path} -noout -check -passin pass:{TEST_PASSWORD}", cwd=workspace.root)


def test_host_import_key_and_issue(workspace):
    """Test importing a host key and then issuing a certificate for it."""
    # 1. Create a CA
    workspace.create_ca()

    # 2. Create an external host key with openssl
    external_host_dir = workspace.root / "external_host"
    external_host_dir.mkdir()
    external_host_key = external_host_dir / "host.key"
    openssl_run(f"genpkey -algorithm ED25519 -out {external_host_key.name}", cwd=external_host_dir)
    original_pubkey = openssl_run(f"pkey -in {external_host_key} -pubout", cwd=workspace.root).stdout

    # 3. Configure the host in hosts.yaml
    hosts_config = {"hosts": {"server_imported": {"common_name": "imported.key.local", "key_algorithm": "ED25519"}}}
    workspace.set_hosts_config(hosts_config)

    # 4. Import the key
    result = workspace.run(
        ["host", "import-key", "server_imported", "--key", str(external_host_key)],
        # Password for host key (none), master password
        password_input=f"\n{TEST_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "Key imported successfully for [bold]server_imported[/bold]" in result.output

    # 5. Issue the certificate
    workspace.issue_host("server_imported")

    # 6. Verify the issued certificate uses the imported key
    host_cert_path = workspace.store_dir / "hosts" / "server_imported" / "cert.crt"
    cert_pubkey = openssl_run(f"x509 -in {host_cert_path} -noout -pubkey", cwd=workspace.root).stdout
    assert cert_pubkey.strip() == original_pubkey.strip()


def test_host_export_key(populated_workspace):
    """Test exporting an unencrypted host key."""
    ws = populated_workspace
    exported_key_path = ws.root / "server1_unencrypted.key"

    # Export the key
    result = ws.run(
        ["host", "export-key", "server1", "--out", str(exported_key_path)],
        password_input=f"{TEST_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert f"Unencrypted key exported to [bold]{exported_key_path}[/bold]" in result.output

    # Verify the exported key is a valid, unencrypted key
    assert "BEGIN EC PRIVATE KEY" in exported_key_path.read_text()
    openssl_run(f"ec -in {exported_key_path.name} -noout -check", cwd=exported_key_path.parent)


def test_host_sign_csr(workspace):
    """Test signing an external Certificate Signing Request."""
    # 1. Create a CA
    workspace.create_ca()

    # 2. Create an external key and CSR with openssl
    external_csr_dir = workspace.root / "external_csr"
    external_csr_dir.mkdir()
    csr_key = external_csr_dir / "csr.key"
    csr_file = external_csr_dir / "csr.pem"
    openssl_run(
        f"req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
        f"-keyout {csr_key.name} -out {csr_file.name} "
        '-subj "/CN=csr.test.local/O=CSR Test Org" '
        '-addext "subjectAltName = DNS:alt.csr.test,IP:10.10.10.10"',
        cwd=external_csr_dir,
    )

    # 3. Sign the CSR with ReactorCA
    signed_cert_path = external_csr_dir / "signed.crt"
    result = ws.run(
        [
            "host",
            "sign-csr",
            "--csr",
            str(csr_file),
            "--out",
            str(signed_cert_path),
            "--validity-days",
            "180",
        ],
        password_input=f"{TEST_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "Successfully signed CSR for [bold]csr.test.local[/bold]" in result.output

    # 4. Verify the signed certificate
    assert signed_cert_path.exists()
    ca_cert_path = workspace.store_dir / "ca" / "ca.crt"
    openssl_run(f"verify -CAfile {ca_cert_path} {signed_cert_path}", cwd=workspace.root)

    cert_info = openssl_run(f"x509 -in {signed_cert_path} -noout -text", cwd=workspace.root)
    assert "Issuer: CN = Reactor CA" in cert_info.stdout
    assert "Subject: CN = csr.test.local" in cert_info.stdout
    assert "O = CSR Test Org" in cert_info.stdout
    assert "DNS:alt.csr.test" in cert_info.stdout
    assert "IP Address:10.10.10.10" in cert_info.stdout
