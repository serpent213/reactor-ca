"""Tests for the cryptographic features of ReactorCA."""


from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

from reactor_ca.ca_operations import generate_key, get_hash_algorithm


def test_generate_key_rsa() -> None:
    """Test RSA key generation."""
    key = generate_key(key_algorithm="RSA2048")
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_generate_key_ec() -> None:
    """Test EC key generation."""
    key = generate_key(key_algorithm="ECP256")
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)

    key = generate_key(key_algorithm="ECP384")
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP384R1)

    key = generate_key(key_algorithm="ECP521")
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP521R1)


def test_generate_key_ed25519() -> None:
    """Test Ed25519 key generation."""
    key = generate_key(key_algorithm="ED25519")
    assert isinstance(key, ed25519.Ed25519PrivateKey)


def test_generate_key_ed448() -> None:
    """Test Ed448 key generation."""
    key = generate_key(key_algorithm="ED448")
    assert isinstance(key, ed448.Ed448PrivateKey)


def test_get_hash_algorithm() -> None:
    """Test hash algorithm retrieval."""
    # Test default
    hash_algo = get_hash_algorithm()
    assert isinstance(hash_algo, SHA256)

    # Test SHA256
    hash_algo = get_hash_algorithm("SHA256")
    assert isinstance(hash_algo, SHA256)

    # Test SHA384
    hash_algo = get_hash_algorithm("SHA384")
    assert isinstance(hash_algo, SHA384)

    # Test SHA512
    hash_algo = get_hash_algorithm("SHA512")
    assert isinstance(hash_algo, SHA512)

    # Test case insensitivity
    hash_algo = get_hash_algorithm("sha256")
    assert isinstance(hash_algo, SHA256)

    # Test invalid algorithm falls back to default
    hash_algo = get_hash_algorithm("INVALID")
    assert isinstance(hash_algo, SHA256)


def test_integration_with_various_algorithms(tmp_path) -> None:
    """Test integration of different key and hash algorithms."""
    # Create a basic test environment
    config_dir = tmp_path / "config"
    certs_dir = tmp_path / "store" / "ca"
    config_dir.mkdir(parents=True)
    certs_dir.mkdir(parents=True)

    # Create minimal config file
    config_content = """
    ca:
      common_name: "Test CA"
      organization: "Test Org"
      organization_unit: "IT"
      country: "US"
      state: "Test State"
      locality: "Test City"
      email: "test@example.com"
      key_algorithm: "{key_algorithm}"
      hash_algorithm: "{hash_algorithm}"
      validity:
        days: 365
      password:
        min_length: 0
    """

    # Test combinations to verify
    test_cases = [
        ("RSA2048", "SHA256"),
        ("RSA4096", "SHA384"),
        ("ECP256", "SHA256"),
        ("ECP384", "SHA384"),
        ("ECP521", "SHA512"),
        ("ED25519", "SHA256"),
        ("ED25519", "SHA512"),
        ("ED448", "SHA384"),
    ]

    for key_algorithm, hash_algorithm in test_cases:
        # Create config with current test case
        curr_config = config_content.format(
            key_algorithm=key_algorithm,
            key_size="",  # Unused in new format
            hash_algorithm=hash_algorithm,
        )

        with open(config_dir / "ca.yaml", "w") as f:
            f.write(curr_config)

        # No need to import here - already imported at the module level

        # Test key generation
        key = generate_key(key_algorithm=key_algorithm)

        if key_algorithm.startswith("RSA"):
            assert isinstance(key, rsa.RSAPrivateKey)
            if key_algorithm == "RSA2048":
                assert key.key_size == 2048
            elif key_algorithm == "RSA3072":
                assert key.key_size == 3072
            elif key_algorithm == "RSA4096":
                assert key.key_size == 4096
        elif key_algorithm.startswith("ECP"):
            assert isinstance(key, ec.EllipticCurvePrivateKey)
            if key_algorithm == "ECP256":
                assert isinstance(key.curve, ec.SECP256R1)
            elif key_algorithm == "ECP384":
                assert isinstance(key.curve, ec.SECP384R1)
            elif key_algorithm == "ECP521":
                assert isinstance(key.curve, ec.SECP521R1)
        elif key_algorithm == "ED25519":
            assert isinstance(key, ed25519.Ed25519PrivateKey)
        elif key_algorithm == "ED448":
            assert isinstance(key, ed448.Ed448PrivateKey)

        # Test hash algorithm
        hash_algo = get_hash_algorithm(hash_algorithm)
        if hash_algorithm == "SHA256":
            assert isinstance(hash_algo, SHA256)
        elif hash_algorithm == "SHA384":
            assert isinstance(hash_algo, SHA384)
        elif hash_algorithm == "SHA512":
            assert isinstance(hash_algo, SHA512)
