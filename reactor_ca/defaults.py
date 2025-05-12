"""Constants, default configurations and templates for ReactorCA."""

import os
from pathlib import Path
from typing import Any

DEFAULT_DIR_ROOT = Path(os.getcwd())
DEFAULT_SUBDIR_CONFIG = "config"
DEFAULT_SUBDIR_STORE = "store"

DEFAULT_PASSWORD_MIN_LENGTH = 12

# Certificate defaults
DEFAULT_CA_HASH_ALGORITHM = "SHA256"
DEFAULT_CA_KEY_ALGORITHM = "RSA4096"
DEFAULT_CA_VALIDITY_DAYS = 3650  # 10 years
DEFAULT_HOST_HASH_ALGORITHM = "SHA256"
DEFAULT_HOST_KEY_ALGORITHM = "RSA2048"
DEFAULT_HOST_VALIDITY_DAYS = 365  # 1 year

# Constants for expiration warnings
EXPIRY_CRITICAL_DAYS = 30
EXPIRY_WARNING_DAYS = 90


def get_default_ca_config() -> dict[str, Any]:
    """Get default CA configuration dictionary."""
    return {
        "ca": {
            "common_name": "Reactor CA",
            "organization": "Reactor Homelab",
            "organization_unit": "IT",
            "country": "DE",
            "state": "Niedersachsen",
            "locality": "Hannover",
            "email": "admin@example.com",
            "key_algorithm": "RSA4096",
            "validity": {
                "years": 10,
            },
        }
    }


# TODO: better create from text incl. comments?
def get_default_hosts_config() -> dict[str, Any]:
    """Get default hosts configuration dictionary."""
    return {
        "hosts": [
            {
                "host_id": "server1",
                "common_name": "server1.example.com",
                "alternative_names": {
                    "dns": [
                        "www.example.com",
                        "api.example.com",
                    ],
                    "ip": [
                        "192.168.1.10",
                    ],
                },
                "export": {
                    "cert": "../path/to/export/cert/server1.pem",
                },
                "deploy": {
                    "command": "cp ${cert} /etc/nginx/ssl/server1.pem "
                    + "&& cp ${private_key} /etc/nginx/ssl/server1.key && systemctl reload nginx",
                },
                "validity": {
                    "years": 1,
                },
                "key_algorithm": DEFAULT_HOST_KEY_ALGORITHM,
            },
        ]
    }
