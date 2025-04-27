# reactorCA Schema Design

## Directory Structure
```
reactorCA/
├── ca/                   # Main script directory
│   ├── __init__.py
│   ├── main.py           # CLI entry point
│   ├── ca_operations.py  # CA functionality
│   ├── cert_operations.py # Certificate operations
│   └── utils.py          # Helper functions
├── config/               # Configuration files
│   ├── ca_config.yaml    # CA configuration
│   └── hosts.yaml        # Host definitions
├── certs/                # Certificate storage
│   ├── ca/               # CA certificates
│   │   ├── ca.crt        # CA certificate
│   │   └── ca.key.enc    # Encrypted CA private key
│   └── hosts/            # Host certificates
│       ├── hostname1/    # One directory per host
│       │   ├── cert.crt  # Certificate
│       │   ├── cert.key.enc # Encrypted private key
│       └── hostname2/
│           └── ...
└── inventory.yaml        # Certificate inventory
```

## Data Structures

### 1. CA Configuration (ca_config.yaml)
```yaml
ca:
  common_name: "Reactor CA"
  organization: "Reactor Homelab"
  organization_unit: "IT"
  country: "DE"
  state: "Berlin"
  locality: "Berlin"
  email: "admin@example.com"
  key:
    algorithm: "RSA"  # Or "EC"
    size: 4096        # Or curve name for EC
  validity_days: 3650   # 10 years
  password:
    min_length: 12
    storage: "session"  # "none", "session", "keyring"
```

### 2. Hosts Configuration (hosts.yaml)
```yaml
hosts:
  - name: "server1.example.com"
    common_name: "server1.example.com"
    alternative_names:
      dns:
        - "www.example.com"
        - "api.example.com"
      ip:
        - "192.168.1.10"
    destination: "../path/to/deploy/cert/server1.pem"
    validity_days: 365
    key:
      algorithm: "RSA"
      size: 2048

  - name: "vpn.example.com"
    common_name: "vpn.example.com"
    alternative_names:
      dns:
        - "vpn1.example.com"
      ip:
        - "192.168.1.20"
    destination: "/var/lib/exim/ssl/server.pem"
    validity_days: 730
```

### 4. Inventory (inventory.yaml)
This optional file provides a quick overview of all certificates:

```yaml
# automatically generated cache file
last_update: "2025-03-16T13:23:59Z"

ca:
  serial: "1234abcd5678efgh"
  not_after: "2033-04-26T23:59:59Z"
  fingerprint: "SHA256:ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv"

hosts:
  - name: "server1.example.com"
    serial: "7829a87d2c3e4f56"
    not_after: "2024-04-26T23:59:59Z"
    fingerprint: "SHA256:12ab34cd56ef78gh90ij12kl34mn56op78qr90st12uv"
    renewal_count: 0

  - name: "vpn.example.com"
    serial: "3f4a5b6c7d8e9f0a"
    not_after: "2025-04-26T23:59:59Z"
    fingerprint: "SHA256:34ef56gh78ij90kl12mn34op56qr78st90uv12ab"
    renewal_count: 1
```

## Key Features

1. **Stateless Operation**: The system can operate without an internal database by:
   - Using random serial numbers for certificates
   - Storing metadata within each host's directory
   - Rebuilding the inventory by scanning the certificate directories
   - Inventory file acts as metadata cache and provides necessary metadata for "list" operations
     - Before opening it for read, recursively scan the certs folder and compare the file timestamps
       to `last_update`. Read metadata from updated files and update the inventory.

2. **Password Management**:
   - Passwords requested once per session
   - All private keys stored encrypted on disk

3. **Git Integration**:
   - Track all configuration files and certificates
   - Never commit private keys
   - Automatic commit messages for certificate operations

4. **Extensibility**:
   - Modular design allows for adding new certificate types
   - Flexibility to support different key algorithms
   - Easy integration with existing certificates and keys
