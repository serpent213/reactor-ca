"""Certificate inventory management."""

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography.x509 import Certificate

from .crypto import load_certificate
from .models import CertificateIdentity, HostCertificateInfo, SubjectIdentity
from .store import Store


@dataclass
class InventoryItem:
    """A certificate in the inventory."""

    hostname: str
    identity: CertificateIdentity
    certificate_info: HostCertificateInfo
    valid_from: datetime
    valid_until: datetime
    is_valid: bool


@dataclass
class Inventory:
    """Certificate inventory tracking all certificates in the store."""

    items: dict[str, InventoryItem] = field(default_factory=dict)

    def add_item(
        self: "Inventory",
        hostname: str,
        identity: CertificateIdentity,
        certificate_info: HostCertificateInfo,
        certificate: Certificate,
    ) -> None:
        """Add a certificate to the inventory."""
        current_time = datetime.now()
        valid_from = certificate.not_valid_before
        valid_until = certificate.not_valid_after
        is_valid = valid_from <= current_time <= valid_until

        self.items[hostname] = InventoryItem(
            hostname=hostname,
            identity=identity,
            certificate_info=certificate_info,
            valid_from=valid_from,
            valid_until=valid_until,
            is_valid=is_valid,
        )

    def get_item(self: "Inventory", hostname: str) -> InventoryItem | None:
        """Get a certificate from the inventory."""
        return self.items.get(hostname)

    def remove_item(self: "Inventory", hostname: str) -> None:
        """Remove a certificate from the inventory."""
        if hostname in self.items:
            del self.items[hostname]

    def is_valid(self: "Inventory", hostname: str) -> bool:
        """Check if a certificate is valid."""
        item = self.get_item(hostname)
        if item is None:
            return False
        return item.is_valid

    def list_valid(self: "Inventory") -> list[str]:
        """List all valid certificates."""
        return [hostname for hostname, item in self.items.items() if item.is_valid]

    def list_invalid(self: "Inventory") -> list[str]:
        """List all invalid certificates."""
        return [hostname for hostname, item in self.items.items() if not item.is_valid]

    def list_all(self: "Inventory") -> list[str]:
        """List all certificates."""
        return list(self.items.keys())


def get_inventory(store: Store) -> Inventory:
    """Build inventory from store."""
    inventory = Inventory()

    # Traverse the store to build the inventory
    store_dir = store.store_dir
    if not os.path.exists(store_dir):
        return inventory

    for hostname in os.listdir(store_dir):
        host_dir = Path(store_dir) / hostname
        if not host_dir.is_dir():
            continue

        # Read certificate and identity information
        cert_path = host_dir / "cert.pem"
        if not cert_path.exists():
            continue

        try:
            # Load the certificate
            certificate = load_certificate(cert_path)

            # Extract identity and certificate info from the certificate
            identity = CertificateIdentity(subject=SubjectIdentity(hostname=hostname))

            # Create certificate info with basic details
            certificate_info = HostCertificateInfo()

            # Add to inventory
            inventory.add_item(hostname, identity, certificate_info, certificate)
        except Exception:
            # Skip certificates that can't be loaded
            pass

    return inventory


def list_certificates(store: Store) -> dict[str, dict]:
    """List all certificates with their details."""
    inventory = get_inventory(store)
    result = {}

    for hostname, item in inventory.items.items():
        result[hostname] = {
            "hostname": item.hostname,
            "valid_from": item.valid_from.isoformat(),
            "valid_until": item.valid_until.isoformat(),
            "is_valid": item.is_valid,
        }

    return result


def get_certificate_details(store: Store, hostname: str) -> dict | None:
    """Get details for a specific certificate."""
    inventory = get_inventory(store)
    item = inventory.get_item(hostname)

    if item is None:
        return None

    return {
        "hostname": item.hostname,
        "valid_from": item.valid_from.isoformat(),
        "valid_until": item.valid_until.isoformat(),
        "is_valid": item.is_valid,
    }


def clean_certificates(store: Store, configured_hosts: list[str]) -> list[str]:
    """Remove certificates for hosts that are not configured."""
    inventory = get_inventory(store)
    removed_hosts = []

    for hostname in inventory.list_all():
        if hostname not in configured_hosts:
            # Remove the certificate from the store
            host_dir = os.path.join(store.store_dir, hostname)
            if os.path.isdir(host_dir):
                import shutil

                shutil.rmtree(host_dir)
                removed_hosts.append(hostname)

    return removed_hosts
