"""Certificate inventory management.

This module provides functions for managing certificate inventory in the ReactorCA store.
All inventory YAML handling is contained here.
"""

import datetime
import logging
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from reactor_ca.models import (
    CAInventoryEntry,
    Inventory,
    InventoryEntry,
    Store,
)
from reactor_ca.paths import get_inventory_path
from reactor_ca.result import Failure, Result, Success

# Setup logging
logger = logging.getLogger(__name__)

# Initialize YAML parser
yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


def read_inventory(store_path: Path) -> Result[Inventory, str]:
    """Read the certificate inventory from the store.

    Args:
    ----
        store_path: Path to the store directory

    Returns:
    -------
        Result with Inventory or error message

    """
    inventory_path = get_inventory_path(store_path)

    if not inventory_path.exists():
        # Create empty inventory structure
        now = datetime.datetime.now(datetime.UTC)
        empty_ca_entry = CAInventoryEntry(
            serial="",
            not_before=now,
            not_after=now,
            fingerprint_sha256="",
        )

        return Success(Inventory(ca=empty_ca_entry, hosts=[]))

    try:
        with open(inventory_path, encoding="utf-8") as f:
            inventory_data = yaml.load(f)

        # Convert raw inventory data to structured Inventory
        ca_data = inventory_data.get("ca", {})
        hosts_data = inventory_data.get("hosts", [])

        # Create CA inventory entry
        if ca_data:
            ca_entry = CAInventoryEntry(
                serial=ca_data.get("serial", ""),
                not_before=datetime.datetime.fromisoformat(
                    ca_data.get("not_before", datetime.datetime.now(datetime.UTC).isoformat())
                ),
                not_after=datetime.datetime.fromisoformat(
                    ca_data.get("not_after", datetime.datetime.now(datetime.UTC).isoformat())
                ),
                fingerprint_sha256=ca_data.get("fingerprint", ""),
                renewal_count=ca_data.get("renewal_count", 0),
                rekey_count=ca_data.get("rekey_count", 0),
            )
        else:
            # Create empty CA entry if none exists
            now = datetime.datetime.now(datetime.UTC)
            ca_entry = CAInventoryEntry(
                serial="",
                not_before=now,
                not_after=now,
                fingerprint_sha256="",
            )

        # Create host inventory entries
        host_entries = []
        for host_data in hosts_data:
            host_entry = InventoryEntry(
                short_name=host_data.get("name", ""),
                serial=host_data.get("serial", ""),
                not_before=datetime.datetime.fromisoformat(
                    host_data.get("not_before", datetime.datetime.now(datetime.UTC).isoformat())
                ),
                not_after=datetime.datetime.fromisoformat(
                    host_data.get("not_after", datetime.datetime.now(datetime.UTC).isoformat())
                ),
                fingerprint_sha256=host_data.get("fingerprint", ""),
                renewal_count=host_data.get("renewal_count", 0),
                rekey_count=host_data.get("rekey_count", 0),
            )
            host_entries.append(host_entry)

        inventory = Inventory(ca=ca_entry, hosts=host_entries)
        return Success(inventory)
    except Exception as e:
        return Failure(f"Failed to load inventory: {str(e)}")


def write_inventory(store_path: Path, inventory: Inventory) -> Result[None, str]:
    """Write the certificate inventory to the store.

    Args:
    ----
        store_path: Path to the store directory
        inventory: Inventory to write

    Returns:
    -------
        Result with None for success or error message

    """
    inventory_path = get_inventory_path(store_path)

    try:
        # Ensure parent directory exists
        inventory_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert inventory to dictionary format
        inventory_dict = {
            "last_update": datetime.datetime.now(datetime.UTC).isoformat(),
            "ca": {
                "serial": inventory.ca.serial,
                "not_before": inventory.ca.not_before.isoformat(),
                "not_after": inventory.ca.not_after.isoformat(),
                "fingerprint": inventory.ca.fingerprint_sha256,
                "renewal_count": inventory.ca.renewal_count,
                "rekey_count": inventory.ca.rekey_count,
            },
            "hosts": [
                {
                    "name": host.short_name,
                    "serial": host.serial,
                    "not_before": host.not_before.isoformat(),
                    "not_after": host.not_after.isoformat(),
                    "fingerprint": host.fingerprint_sha256,
                    "renewal_count": host.renewal_count,
                    "rekey_count": host.rekey_count,
                }
                for host in inventory.hosts
            ],
        }

        # Write inventory
        with open(inventory_path, "w", encoding="utf-8") as f:
            yaml.dump(inventory_dict, f)

        logger.debug(f"Saved inventory to {inventory_path}")
        return Success(None)
    except Exception as e:
        return Failure(f"Failed to write inventory: {str(e)}")


def update_inventory_with_ca_cert(
    store_path: Path, cert: x509.Certificate, inventory: Inventory
) -> Result[Inventory, str]:
    """Update inventory with CA certificate information.

    Args:
    ----
        store_path: Path to the store directory
        cert: CA certificate to update inventory with
        inventory: Current inventory

    Returns:
    -------
        Result with updated Inventory or error message

    """
    try:
        # Update CA inventory entry
        inventory.ca = CAInventoryEntry.from_certificate(cert)
        return Success(inventory)
    except Exception as e:
        return Failure(f"Failed to update CA entry in inventory: {str(e)}")


def update_inventory_with_host_cert(
    store_path: Path,
    host_id: str,
    cert: x509.Certificate,
    inventory: Inventory,
    rekeyed: bool = False,
    renewal_count_increment: int = 1,
) -> Result[Inventory, str]:
    """Update inventory with host certificate information.

    Args:
    ----
        store_path: Path to the store directory
        host_id: Host identifier
        cert: Certificate to update inventory with
        inventory: Current inventory
        rekeyed: Whether the certificate was rekeyed
        renewal_count_increment: Amount to increment renewal count

    Returns:
    -------
        Result with updated Inventory or error message

    """
    try:
        # Find existing host entry or create new one
        for i, host in enumerate(inventory.hosts):
            if host.short_name == host_id:
                # Update existing entry with new certificate info
                updated_entry = InventoryEntry.from_certificate(host_id, cert)
                # Preserve and increment counts
                updated_entry.renewal_count = host.renewal_count + renewal_count_increment
                updated_entry.rekey_count = host.rekey_count + (1 if rekeyed else 0)
                inventory.hosts[i] = updated_entry
                break
        else:
            # Add new entry
            new_entry = InventoryEntry.from_certificate(host_id, cert)
            new_entry.renewal_count = renewal_count_increment
            new_entry.rekey_count = 1 if rekeyed else 0
            inventory.hosts.append(new_entry)

        return Success(inventory)
    except Exception as e:
        return Failure(f"Failed to update host entry in inventory: {str(e)}")


def delete_host_from_inventory(store_path: Path, host_id: str) -> Result[None, str]:
    """Delete a host from the inventory.

    Args:
    ----
        store_path: Path to the store directory
        host_id: Host identifier

    Returns:
    -------
        Result with None for success or error message

    """
    inventory_result = read_inventory(store_path)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()

    # Remove host from inventory
    inventory.hosts = [host for host in inventory.hosts if host.short_name != host_id]

    # Write updated inventory
    return write_inventory(store_path, inventory)


def get_host_info(store_path: Path, host_id: str, cert: x509.Certificate = None) -> Result[dict[str, Any], str]:
    """Get certificate information for a host.

    Args:
    ----
        store_path: Path to the store directory
        host_id: Host identifier
        cert: Optional certificate for additional information

    Returns:
    -------
        Result with host info dictionary or error message

    """
    # Read inventory
    inventory_result = read_inventory(store_path)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()

    # Find host in inventory
    for host in inventory.hosts:
        if host.short_name == host_id:
            # Convert to dictionary
            host_info = {
                "name": host.short_name,
                "serial": host.serial,
                "not_before": host.not_before.isoformat(),
                "not_after": host.not_after.isoformat(),
                "fingerprint": host.fingerprint_sha256,
                "renewal_count": host.renewal_count,
                "rekey_count": host.rekey_count,
            }

            # Add additional details from certificate if available
            if cert:
                # Calculate days until expiry
                now = datetime.datetime.now(datetime.UTC)
                expiry = cert.not_valid_after
                delta = expiry - now

                host_info["days_until_expiry"] = delta.days

                # Add subject information
                subject = cert.subject
                host_info["subject"] = {}

                for attr in subject:
                    host_info["subject"][attr.oid._name] = attr.value

            return Success(host_info)

    return Failure(f"Host {host_id} not found in inventory")


def list_hosts_from_inventory(store_path: Path) -> Result[dict[str, dict], str]:
    """List all hosts in the inventory with their details.

    Args:
    ----
        store_path: Path to the store directory

    Returns:
    -------
        Result with a dictionary of host information

    """
    inventory_result = read_inventory(store_path)
    if not inventory_result:
        return Failure(f"Failed to read inventory: {inventory_result.error}")

    inventory = inventory_result.unwrap()
    result = {}

    for host in inventory.hosts:
        result[host.short_name] = {
            "hostname": host.short_name,
            "valid_from": host.not_before.isoformat(),
            "valid_until": host.not_after.isoformat(),
            "is_valid": host.not_before <= datetime.datetime.now(datetime.UTC) <= host.not_after,
        }

    return Success(result)