"""Default configurations and templates for ReactorCA."""

from typing import Any

# Default validity periods
DEFAULT_HOST_VALIDITY_DAYS = 365  # 1 year
DEFAULT_CA_VALIDITY_DAYS = 3650  # 10 years


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
            "password": {
                "min_length": 12,
                "file": "",
                "env_var": "REACTOR_CA_PASSWORD",
            },
        }
    }


def get_default_hosts_config() -> dict[str, Any]:
    """Get default hosts configuration dictionary."""
    return {
        "hosts": [
            {
                "name": "server1.example.com",
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
                    "chain": "../path/to/export/cert/server1-chain.pem",
                },
                "deploy": {
                    "command": "cp ${cert} /etc/nginx/ssl/server1.pem "
                    + "&& cp ${private_key} /etc/nginx/ssl/server1.key && systemctl reload nginx",
                },
                "validity": {
                    "years": 1,
                },
                "key_algorithm": "RSA2048",
            },
        ]
    }
