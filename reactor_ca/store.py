"""Certificate Store and Inventory Management.

This module provides an abstraction layer for managing certificate storage,
inventory tracking, and file operations for the ReactorCA tool.
"""

import datetime
import logging
import os
from getpass import getpass
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

# Setup logging
logger = logging.getLogger(__name__)


class Store:
    """Certificate Store management class that provides an abstraction layer.

    This class handles all file operations, inventory tracking, and certificate storage
    for ReactorCA.
    """

    def __init__(self: "Store", root_dir: str | None = None) -> None:
        """Initialize the store with root directory.

        Args:
        ----
            root_dir: Optional root directory override (defaults to current directory)

        """
        # Set up root directory
        self.root_dir = Path(root_dir if root_dir else ".")

        # Define important paths
        self.store_dir = self.root_dir / "store"
        self.config_dir = self.root_dir / "config"
        self.ca_dir = self.store_dir / "ca"
        self.hosts_dir = self.store_dir / "hosts"
        self.inventory_path = self.store_dir / "inventory.yaml"

        # Password for private key operations
        self._password: str | None = None
        self._unlocked = False

    def init(self: "Store") -> None:
        """Initialize the certificate store directory structure.

        Creates necessary folders if they don't exist.
        """
        # Create the main directories
        self.store_dir.mkdir(exist_ok=True, parents=True)
        self.config_dir.mkdir(exist_ok=True, parents=True)
        self.ca_dir.mkdir(exist_ok=True, parents=True)
        self.hosts_dir.mkdir(exist_ok=True, parents=True)

        # Initialize inventory if it doesn't exist
        if not self.inventory_path.exists():
            self._save_inventory(
                {
                    "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
                    "ca": {},
                    "hosts": [],
                }
            )

        logger.info(f"Initialized certificate store at {self.root_dir}")

    def unlock(self: "Store", password: str | None = None, ca_init: bool = False) -> bool:
        """Unlock the store with the provided password.

        If password is not provided, prompt the user.

        Args:
        ----
            password: Optional password to unlock the store
            ca_init: Whether this is for CA initialization (skip validation)

        Returns:
        -------
            bool: True if unlocking was successful

        """
        # Load config for password validation
        config = self.load_config()
        min_length = config["ca"]["password"]["min_length"]
        password_file = config["ca"]["password"].get("file", "")
        env_var = config["ca"]["password"].get("env_var", "")

        # If already unlocked with a password, return success
        if self._unlocked and self._password:
            return True

        # Try to get password from file if specified
        if password_file and not password:
            password = self._read_password_from_file(password_file)

        # Try to get password from environment variable if specified
        if env_var and not password and env_var in os.environ:
            password = os.environ[env_var]

        # If still no password, prompt the user
        if not password:
            password = getpass("Enter CA master password: ")
            if ca_init:
                confirm = getpass("Confirm CA master password: ")
                if password != confirm:
                    logger.error("Passwords do not match")
                    return False

        # Validate password length
        if len(password) < min_length:
            logger.error(f"Password must be at least {min_length} characters long")
            return False

        # If in CA init mode, just store password without validation
        if ca_init:
            self._password = password
            self._unlocked = True
            logger.debug("CA store unlocked for initialization")
            return True

        # Validate against CA key if it exists and not in init mode
        ca_key_path = self.ca_dir / "ca.key.enc"
        if ca_key_path.exists():
            try:
                # Try to load it to verify the password
                with open(ca_key_path, "rb") as f:
                    key_data = f.read()
                    load_pem_private_key(key_data, password.encode("utf-8"))
                self._password = password
                self._unlocked = True
                logger.debug("CA store unlocked successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to unlock CA store: {e}")
                return False
        else:
            # If key doesn't exist yet, store password for later use
            self._password = password
            self._unlocked = True
            return True

    def _read_password_from_file(self: "Store", password_file: str) -> str | None:
        """Read password from a file.

        Args:
        ----
            password_file: Path to the password file

        Returns:
        -------
            Password string if found, None if error occurred

        """
        try:
            with open(password_file) as f:
                password = f.read().strip()
                return password
        except Exception as e:
            logger.error(f"Error reading password file: {e}")
            return None

    @property
    def is_unlocked(self: "Store") -> bool:
        """Check if the store is currently unlocked.

        Returns
        -------
            True if store is unlocked with a valid password

        """
        return self._unlocked and self._password is not None

    def require_unlock(self: "Store") -> None:
        """Ensure the store is unlocked or raise an exception.

        Raises
        ------
            RuntimeError: If the store is locked

        """
        if not self.is_unlocked:
            raise RuntimeError("Certificate store is locked. Call unlock() first.")

    def _ensure_password_is_str(self: "Store", password: str | None) -> str | None:
        """Ensure password is a string or None, not bytes.

        Args:
        ----
            password: Password to validate

        Returns:
        -------
            Password as string or None

        """
        if password is None:
            return None
        return password

    def load_config(self: "Store") -> dict[str, Any]:
        """Load CA configuration.

        Returns
        -------
            Dictionary containing CA configuration

        """
        config_path = self.config_dir / "ca.yaml"

        if not config_path.exists():
            logger.warning(f"Configuration file not found at {config_path}")
            return self._get_default_config()

        try:
            with open(config_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return self._get_default_config()

    def load_hosts_config(self: "Store") -> dict[str, Any]:
        """Load hosts configuration.

        Returns
        -------
            Dictionary containing hosts configuration

        """
        hosts_path = self.config_dir / "hosts.yaml"

        if not hosts_path.exists():
            logger.warning(f"Hosts configuration file not found at {hosts_path}")
            return {"hosts": []}

        try:
            with open(hosts_path) as f:
                hosts_config = yaml.safe_load(f)
                if not isinstance(hosts_config, dict):
                    return {"hosts": []}
                return hosts_config
        except Exception as e:
            logger.error(f"Failed to load hosts configuration: {e}")
            return {"hosts": []}

    def _get_default_config(self: "Store") -> dict[str, Any]:
        """Get default CA configuration.

        Returns
        -------
            Dictionary containing default CA configuration

        """
        return {
            "ca": {
                "common_name": "Reactor CA",
                "country": "US",
                "state": "CA",
                "locality": "San Francisco",
                "organization": "Reactor",
                "organizational_unit": "IT",
                "validity": 3650,  # 10 years
                "key_size": 4096,
                "password": {
                    "min_length": 12,
                    "file": "",
                    "env_var": "",
                },
            }
        }

    def create_default_config(self: "Store") -> None:
        """Create default configuration files if they don't exist.

        This creates both ca.yaml and hosts.yaml with reasonable defaults.
        """
        # CA config
        ca_config_path = self.config_dir / "ca.yaml"
        if not ca_config_path.exists():
            self.config_dir.mkdir(exist_ok=True, parents=True)
            ca_config = self._get_default_config()

            with open(ca_config_path, "w") as f:
                f.write("# ReactorCA Configuration\n")
                f.write("# This file contains settings for the Certificate Authority\n")
                f.write("# It is safe to modify this file directly\n\n")
                yaml.dump(ca_config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Created default CA configuration at {ca_config_path}")

        # Hosts config
        hosts_config_path = self.config_dir / "hosts.yaml"
        if not hosts_config_path.exists():
            hosts_config: dict[str, list] = {"hosts": []}

            with open(hosts_config_path, "w") as f:
                f.write("# ReactorCA Hosts Configuration\n")
                f.write("# This file contains settings for host certificates\n")
                f.write("# It is safe to modify this file directly\n\n")
                yaml.dump(hosts_config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Created default hosts configuration at {hosts_config_path}")

    def get_ca_cert_path(self: "Store") -> Path:
        """Get the path to the CA certificate."""
        return self.ca_dir / "ca.crt"

    def get_ca_key_path(self: "Store") -> Path:
        """Get the path to the CA private key."""
        return self.ca_dir / "ca.key.enc"

    def get_host_dir(self: "Store", hostname: str) -> Path:
        """Get the directory for a host's certificates and keys."""
        return self.hosts_dir / hostname

    def get_host_cert_path(self: "Store", hostname: str) -> Path:
        """Get the path to a host certificate."""
        return self.get_host_dir(hostname) / "cert.crt"

    def get_host_key_path(self: "Store", hostname: str) -> Path:
        """Get the path to a host private key."""
        return self.get_host_dir(hostname) / "cert.key.enc"

    def get_crl_path(self: "Store") -> Path:
        """Get the path to the certificate revocation list."""
        return self.ca_dir / "ca.crl"

    def ensure_directory_exists(self: "Store", path: Path) -> Path:
        """Ensure a directory exists, creating it if necessary."""
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_ca_cert(self: "Store", cert: x509.Certificate) -> Path:
        """Save the CA certificate to the store.

        Args:
        ----
            cert: The CA certificate object

        Returns:
        -------
            Path: The path where the cert was saved

        """
        cert_path = self.get_ca_cert_path()
        self.ensure_directory_exists(cert_path.parent)
        cert_bytes = cert.public_bytes(Encoding.PEM)

        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Saved CA certificate to {cert_path}")

        # Update inventory
        self.update_inventory()

        return cert_path

    def save_ca_key(self: "Store", private_key: PrivateKeyTypes) -> Path:
        """Save the CA private key to the store.

        The key will be encrypted with the store password.

        Args:
        ----
            private_key: RSA private key object

        Returns:
        -------
            Path: The path where the key was saved

        """
        self.require_unlock()
        key_path = self.get_ca_key_path()
        self.ensure_directory_exists(key_path.parent)

        # Ensure password exists
        if self._password is None:
            raise ValueError("Cannot save encrypted key: no password available")

        # Encrypt with password
        encryption = BestAvailableEncryption(self._password.encode("utf-8"))
        key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

        with open(key_path, "wb") as f:
            f.write(key_bytes)

        logger.info(f"Saved encrypted CA private key to {key_path}")
        return key_path

    def save_host_cert(self: "Store", hostname: str, cert: x509.Certificate) -> Path:
        """Save a host certificate to the store.

        Args:
        ----
            hostname: Host name
            cert: Certificate object

        Returns:
        -------
            Path: Path where the certificate was saved

        """
        cert_path = self.get_host_cert_path(hostname)
        self.ensure_directory_exists(cert_path.parent)
        cert_bytes = cert.public_bytes(Encoding.PEM)

        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Saved certificate for {hostname} to {cert_path}")

        # Update inventory
        self.update_inventory()

        return cert_path

    def save_host_key(self: "Store", hostname: str, private_key: PrivateKeyTypes) -> Path:
        """Save a host private key to the store.

        Args:
        ----
            hostname: Host name
            private_key: RSA private key object

        Returns:
        -------
            Path: Path where the key was saved

        """
        self.require_unlock()
        key_path = self.get_host_key_path(hostname)
        self.ensure_directory_exists(key_path.parent)

        # Ensure password exists
        if self._password is None:
            raise ValueError("Cannot save encrypted key: no password available")

        # Encrypt with password
        encryption = BestAvailableEncryption(self._password.encode("utf-8"))
        key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

        with open(key_path, "wb") as f:
            f.write(key_bytes)

        logger.info(f"Saved encrypted private key for {hostname} to {key_path}")
        return key_path

    def save_crl(self: "Store", crl: x509.CertificateRevocationList) -> Path:
        """Save a Certificate Revocation List to the store.

        Args:
        ----
            crl: CertificateRevocationList object

        Returns:
        -------
            Path: Path where the CRL was saved

        """
        crl_path = self.get_crl_path()
        self.ensure_directory_exists(crl_path.parent)
        crl_bytes = crl.public_bytes(Encoding.PEM)

        with open(crl_path, "wb") as f:
            f.write(crl_bytes)

        logger.info(f"Saved CRL to {crl_path}")
        return crl_path

    def load_ca_cert(self: "Store") -> x509.Certificate | None:
        """Load the CA certificate from the store.

        Returns
        -------
            x509.Certificate or None: The CA certificate if it exists

        """
        cert_path = self.get_ca_cert_path()
        if not cert_path.exists():
            logger.warning(f"CA certificate not found at {cert_path}")
            return None

        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)

        logger.debug(f"Loaded CA certificate from {cert_path}")
        return cert

    def load_ca_key(self: "Store") -> PrivateKeyTypes | None:
        """Load the CA private key from the store.

        Returns
        -------
            PrivateKeyTypes or None: The CA private key if it exists

        """
        self.require_unlock()
        key_path = self.get_ca_key_path()
        if not key_path.exists():
            logger.warning(f"CA private key not found at {key_path}")
            return None

        if self._password is None:
            logger.error("No password available to decrypt the key")
            return None

        with open(key_path, "rb") as f:
            key_data = f.read()
            key = load_pem_private_key(key_data, self._password.encode("utf-8"))

        logger.debug(f"Loaded CA private key from {key_path}")
        return key

    def load_host_cert(self: "Store", hostname: str) -> x509.Certificate | None:
        """Load a host certificate from the store.

        Args:
        ----
            hostname: Host name

        Returns:
        -------
            x509.Certificate or None: The certificate if it exists

        """
        cert_path = self.get_host_cert_path(hostname)
        if not cert_path.exists():
            logger.warning(f"Certificate for {hostname} not found at {cert_path}")
            return None

        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)

        logger.debug(f"Loaded certificate for {hostname} from {cert_path}")
        return cert

    def load_host_key(self: "Store", hostname: str) -> PrivateKeyTypes | None:
        """Load a host private key from the store.

        Args:
        ----
            hostname: Host name

        Returns:
        -------
            PrivateKeyTypes or None: The private key if it exists

        """
        self.require_unlock()
        key_path = self.get_host_key_path(hostname)
        if not key_path.exists():
            logger.warning(f"Private key for {hostname} not found at {key_path}")
            return None

        if self._password is None:
            logger.error("No password available to decrypt the key")
            return None

        with open(key_path, "rb") as f:
            key_data = f.read()
            try:
                key = load_pem_private_key(key_data, self._password.encode("utf-8"))
                logger.debug(f"Loaded encrypted private key for {hostname} from {key_path}")
                return key
            except Exception as e:
                logger.error(f"Failed to load private key for {hostname}: {e}")
                return None

    def load_crl(self: "Store") -> x509.CertificateRevocationList | None:
        """Load the Certificate Revocation List from the store.

        Returns
        -------
            x509.CertificateRevocationList or None: The CRL if it exists

        """
        crl_path = self.get_crl_path()
        if not crl_path.exists():
            logger.warning(f"CRL not found at {crl_path}")
            return None

        with open(crl_path, "rb") as f:
            crl_data = f.read()
            crl = x509.load_pem_x509_crl(crl_data)

        logger.debug(f"Loaded CRL from {crl_path}")
        return crl

    def ca_cert_exists(self: "Store") -> bool:
        """Check if CA certificate exists in the store."""
        return self.get_ca_cert_path().exists()

    def ca_key_exists(self: "Store") -> bool:
        """Check if CA private key exists in the store."""
        return self.get_ca_key_path().exists()

    def host_cert_exists(self: "Store", hostname: str) -> bool:
        """Check if a host certificate exists in the store."""
        return self.get_host_cert_path(hostname).exists()

    def host_key_exists(self: "Store", hostname: str) -> bool:
        """Check if a host private key exists in the store."""
        return self.get_host_key_path(hostname).exists()

    def crl_exists(self: "Store") -> bool:
        """Check if CRL exists in the store."""
        return self.get_crl_path().exists()

    def _load_inventory(self: "Store") -> dict[str, Any]:
        """Load the certificate inventory."""
        if not self.inventory_path.exists():
            # Create empty inventory
            inventory = {
                "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
                "ca": {},
                "hosts": [],
            }
            self._save_inventory(inventory)
            return inventory

        with open(self.inventory_path) as f:
            try:
                return yaml.safe_load(f)
            except Exception as e:
                logger.error(f"Failed to parse inventory file at {self.inventory_path}: {e}")
                # Return empty inventory as fallback
                return {
                    "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
                    "ca": {},
                    "hosts": [],
                }

    def _save_inventory(self: "Store", inventory: dict[str, Any]) -> None:
        """Save the certificate inventory."""
        self.ensure_directory_exists(self.inventory_path.parent)

        with open(self.inventory_path, "w") as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)

        logger.debug(f"Saved inventory to {self.inventory_path}")

    def update_inventory(self: "Store") -> dict[str, Any]:
        """Update inventory based on certificate files.

        Returns
        -------
            Dict: The updated inventory

        """
        inventory = self._load_inventory()

        # Check CA certificate
        ca_cert_path = self.get_ca_cert_path()
        if ca_cert_path.exists():
            try:
                ca_cert = self.load_ca_cert()
                if ca_cert:
                    inventory["ca"] = {
                        "serial": format(ca_cert.serial_number, "x"),
                        "not_after": ca_cert.not_valid_after.isoformat(),
                        "fingerprint": "SHA256:" + ca_cert.fingerprint(hashes.SHA256()).hex(),
                    }
            except Exception as e:
                logger.error(f"Error loading CA certificate: {e}")

        # Check host certificates
        if self.hosts_dir.exists():
            host_dirs = [d for d in self.hosts_dir.iterdir() if d.is_dir()]

            for host_dir in host_dirs:
                hostname = host_dir.name
                cert_path = host_dir / "cert.crt"

                if cert_path.exists():
                    try:
                        cert = self.load_host_cert(hostname)
                        if cert:
                            # Find existing host entry or create new one
                            for host in inventory.setdefault("hosts", []):
                                if host["name"] == hostname:
                                    host["serial"] = format(cert.serial_number, "x")
                                    host["not_after"] = cert.not_valid_after.isoformat()
                                    host["fingerprint"] = "SHA256:" + cert.fingerprint(hashes.SHA256()).hex()
                                    # Keep renewal count if exists
                                    break
                            else:
                                # Add new entry if not found
                                inventory.setdefault("hosts", []).append(
                                    {
                                        "name": hostname,
                                        "serial": format(cert.serial_number, "x"),
                                        "not_after": cert.not_valid_after.isoformat(),
                                        "fingerprint": "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(),
                                        "renewal_count": 0,
                                    }
                                )
                    except Exception as e:
                        logger.error(f"Error loading certificate for {hostname}: {e}")

        # Update last_update timestamp
        inventory["last_update"] = datetime.datetime.now(datetime.UTC).isoformat()

        # Save updated inventory
        self._save_inventory(inventory)

        return inventory

    def get_hosts(self: "Store") -> list[str]:
        """Get list of hosts with certificates.

        Returns
        -------
            List[str]: List of hostnames

        """
        inventory = self._load_inventory()
        return [host["name"] for host in inventory.get("hosts", [])]

    def get_host_info(self: "Store", hostname: str) -> dict[str, Any] | None:
        """Get certificate information for a host.

        Args:
        ----
            hostname: Host name

        Returns:
        -------
            Dict or None: Host certificate information if it exists

        """
        inventory = self._load_inventory()

        for host in inventory.get("hosts", []):
            if host["name"] == hostname:
                return host

        return None

    def get_ca_info(self: "Store") -> dict[str, Any] | None:
        """Get certificate information for the CA.

        Returns
        -------
            Dict or None: CA information if it exists

        """
        inventory = self._load_inventory()
        return inventory.get("ca")

    def increment_renewal_count(self: "Store", hostname: str) -> None:
        """Increment the renewal count for a host.

        Args:
        ----
            hostname: Host name

        """
        inventory = self._load_inventory()

        for host in inventory.get("hosts", []):
            if host["name"] == hostname:
                host["renewal_count"] = host.get("renewal_count", 0) + 1
                break

        self._save_inventory(inventory)

    def delete_host(self: "Store", hostname: str) -> bool:
        """Delete a host's certificate and key from the store.

        Args:
        ----
            hostname: Host name

        Returns:
        -------
            bool: True if the host was deleted

        """
        host_dir = self.get_host_dir(hostname)

        if not host_dir.exists():
            logger.warning(f"Host directory for {hostname} not found at {host_dir}")
            return False

        # Delete certificate and key
        cert_path = self.get_host_cert_path(hostname)
        key_path = self.get_host_key_path(hostname)

        if cert_path.exists():
            cert_path.unlink()
            logger.info(f"Deleted certificate for {hostname}")

        if key_path.exists():
            key_path.unlink()
            logger.info(f"Deleted private key for {hostname}")

        # Try to remove the directory if it's empty
        try:
            host_dir.rmdir()
            logger.info(f"Removed host directory for {hostname}")
        except OSError:
            # Directory not empty, that's OK
            pass

        # Remove from inventory
        inventory = self._load_inventory()
        inventory["hosts"] = [host for host in inventory.get("hosts", []) if host["name"] != hostname]
        self._save_inventory(inventory)

        return True

    def export_host_cert(self: "Store", hostname: str, output_path: str) -> bool:
        """Export a host certificate to a specified path.

        Args:
        ----
            hostname: Host name
            output_path: Path to export the certificate to

        Returns:
        -------
            bool: True if the certificate was exported

        """
        cert_path = self.get_host_cert_path(hostname)
        if not cert_path.exists():
            logger.warning(f"Certificate for {hostname} not found at {cert_path}")
            return False

        with open(cert_path, "rb") as src:
            with open(output_path, "wb") as dst:
                dst.write(src.read())

        logger.info(f"Exported certificate for {hostname} to {output_path}")
        return True

    def export_host_key(self: "Store", hostname: str, output_path: str, decrypt: bool = False) -> bool:
        """Export a host private key to a specified path.

        Args:
        ----
            hostname: Host name
            output_path: Path to export the key to
            decrypt: Whether to decrypt the key (requires store to be unlocked)

        Returns:
        -------
            bool: True if the key was exported

        """
        if decrypt:
            self.require_unlock()

        key_path = self.get_host_key_path(hostname)
        if not key_path.exists():
            logger.warning(f"Private key for {hostname} not found at {key_path}")
            return False

        if decrypt:
            # Load and decrypt the key, then save without encryption
            try:
                key = self.load_host_key(hostname)
                if key:
                    key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

                    with open(output_path, "wb") as f:
                        f.write(key_bytes)

                    logger.info(f"Exported decrypted private key for {hostname} to {output_path}")
                    return True
                else:
                    return False
            except Exception as e:
                logger.error(f"Failed to export decrypted key for {hostname}: {e}")
                return False
        else:
            # Just copy the encrypted key
            with open(key_path, "rb") as src:
                with open(output_path, "wb") as dst:
                    dst.write(src.read())

            logger.info(f"Exported encrypted private key for {hostname} to {output_path}")
            return True

    def export_ca_cert(self: "Store", output_path: str) -> bool:
        """Export the CA certificate to a specified path.

        Args:
        ----
            output_path: Path to export the certificate to

        Returns:
        -------
            bool: True if the certificate was exported

        """
        cert_path = self.get_ca_cert_path()
        if not cert_path.exists():
            logger.warning(f"CA certificate not found at {cert_path}")
            return False

        with open(cert_path, "rb") as src:
            with open(output_path, "wb") as dst:
                dst.write(src.read())

        logger.info(f"Exported CA certificate to {output_path}")
        return True

    def get_cert_expiry_days(self: "Store", hostname: str | None = None) -> int | None:
        """Get the expiry date of a certificate in days from now.

        Args:
        ----
            hostname: Host name, or None for CA certificate

        Returns:
        -------
            int or None: Days until expiry, or None if certificate not found

        """
        cert = None

        if hostname:
            cert = self.load_host_cert(hostname)
        else:
            cert = self.load_ca_cert()

        if not cert:
            return None

        now = datetime.datetime.now(datetime.UTC)
        expiry = cert.not_valid_after
        delta = expiry - now

        return delta.days


def get_store(root_dir: str | None = None) -> Store:
    """Create a store instance.

    Args:
    ----
        root_dir: Optional root directory override

    Returns:
    -------
        Store: Initialized store instance

    """
    return Store(root_dir)
