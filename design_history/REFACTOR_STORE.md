# Store Module Refactoring for ReactorCA

This document outlines a refactoring plan to transform the `store.py` module from a class-based approach to a functional approach using dataclasses from `models.py`.

## Overview

The current `store.py` module uses a class-based design where a `Store` object maintains state and provides methods for operations on certificates and keys. This proposal redesigns the module to use a functional approach where:

1. All operations use the `Store` dataclass from `models.py` to maintain necessary state
2. Functions have single responsibilities and compose well together
3. Error handling is explicit and consistent using the `Result` pattern
4. Password handling is preserved with an explicit unlock mechanism

### High-Level Design

```
+-------------+       +-------------+       +-------------+
|             |       |             |       |             |
|   models.py |<----->|   store.py  |<----->|  crypto.py  |
| (dataclasses)|       | (functions) |       | (crypto ops)|
|             |       |             |       |             |
+-------------+       +-------------+       +-------------+
       ^                     ^   ^                 ^
       |                     |   |                 |
       |                     v   v                 |
       |        +-------------+  +-------------+   |
       |        |             |  |             |   |
       +------->|   paths.py  |  |   utils.py  |<--+
                | (path utils)|  | (password)  |
                |             |  |             |
                +-------------+  +-------------+
                                        ^
                                        |
                                        v
                                 +-------------+
                                 |             |
                                 |  result.py  |
                                 | (error hdlg)|
                                 |             |
                                 +-------------+
```

This functional design makes the store module more modular, easier to test, and more robust by making all dependencies explicit.

## Design Principles

1. **Pure Functions**: Replace class methods with functions that take and return `Store` objects
2. **Type Safety**: Maintain strong typing throughout, following the project's typing guidelines
3. **Error Handling**: Use the `Result` pattern for operations that might fail
4. **Orthogonality**: Create functions with single responsibilities that compose well
5. **State Management**: Pass and return the `Store` dataclass to maintain state between operations

## Result Pattern for Error Handling

The refactored code will use the `Result` pattern from `result.py` for consistent error handling:

```python
from reactor_ca.result import Result, Success, Failure

def read_ca_cert(store: Store) -> Result[x509.Certificate, str]:
    """
    Read the CA certificate from the store.
    Returns Success with certificate or Failure with error message.
    """
    cert_path = get_ca_cert_path(store)
    if not cert_path.exists():
        return Result.failure(f"CA certificate not found at {cert_path}")

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
        return Result.success(cert)
    except Exception as e:
        return Result.failure(f"Failed to load CA certificate: {str(e)}")
```

This pattern provides several benefits:
- Makes error handling explicit and consistent throughout the codebase
- Allows for composition of operations with the `and_then` method
- Clearly distinguishes between failure states and successful returns
- Includes context about what went wrong in the failure case

## Core Function Groups

### Store Management

```python
def initialize_store(store: Store) -> Result[Store, str]:
    """Initialize the store directory structure and create empty inventory if needed."""
    
def unlock_store(store: Store, password: str | None = None, ca_init: bool = False) -> Result[Store, str]:
    """
    Unlock the store with the provided password.
    
    If password is not provided, tries multiple sources in order:
    1. Password file specified in config
    2. Environment variable specified in config
    3. User prompt
    """
    
def require_unlocked(store: Store) -> Result[Store, str]:
    """Check if the store is unlocked and return error if not."""
```

### Certificate Operations

```python
def read_ca_cert(store: Store) -> Result[x509.Certificate, str]:
    """Read the CA certificate from the store."""
    
def write_ca_cert(store: Store, cert: x509.Certificate) -> Result[Store, str]:
    """Write the CA certificate to the store."""
    
def read_ca_key(store: Store) -> Result[PrivateKeyTypes, str]:
    """Read the encrypted CA private key from the store."""
    
def write_ca_key(store: Store, key: PrivateKeyTypes) -> Result[Store, str]:
    """Write the encrypted CA private key to the store."""
    
def read_host_cert(store: Store, host_id: str) -> Result[x509.Certificate, str]:
    """Read a host certificate from the store."""
    
def write_host_cert(store: Store, host_id: str, cert: x509.Certificate) -> Result[Store, str]:
    """Write a host certificate to the store."""
    
def read_host_key(store: Store, host_id: str) -> Result[PrivateKeyTypes, str]:
    """Read the encrypted host private key from the store."""
    
def write_host_key(store: Store, host_id: str, key: PrivateKeyTypes) -> Result[Store, str]:
    """Write the encrypted host private key to the store."""
```

### Inventory Management

```python
def read_inventory(store: Store) -> Result[Inventory, str]:
    """Read the certificate inventory from the store."""
    
def write_inventory(store: Store, inventory: Inventory) -> Result[Store, str]:
    """Write the certificate inventory to the store."""
    
def update_inventory(store: Store) -> Result[Store, str]:
    """Update inventory based on certificate files."""
    
def update_ca_in_inventory(
    store: Store, 
    cert: x509.Certificate, 
    rekeyed: bool = False
) -> Result[Store, str]:
    """Update CA entry in the inventory."""
    
def update_host_in_inventory(
    store: Store, 
    host_id: str, 
    cert: x509.Certificate, 
    rekeyed: bool = False
) -> Result[Store, str]:
    """Update a host entry in the inventory."""
```

### Path Utilities

```python
def get_ca_cert_path(store: Store) -> Path:
    """Return the path to the CA certificate file."""
    
def get_ca_key_path(store: Store) -> Path:
    """Return the path to the CA private key file."""
    
def get_host_cert_path(store: Store, host_id: str) -> Path:
    """Return the path to a host certificate file."""
    
def get_host_key_path(store: Store, host_id: str) -> Path:
    """Return the path to a host private key file."""
    
def get_host_dir(store: Store, host_id: str) -> Path:
    """Return the path to a host directory."""
    
def get_inventory_path(store: Store) -> Path:
    """Return the path to the inventory file."""
```

### Password Management

```python
def change_password(
    store: Store, 
    old_password: str | None = None, 
    new_password: str | None = None
) -> Result[Store, str]:
    """Change the password for all private keys in the store."""
    
def get_password(store: Store, prompt_message: str = "Enter password: ") -> Result[str, str]:
    """Get a password from the available sources."""
```

### Export Operations

```python
def export_ca_cert(store: Store, export_path: Path) -> Result[None, str]:
    """Export the CA certificate to the specified path."""
    
def export_host_cert(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """Export a host certificate to the specified path."""
    
def export_host_key_unencrypted(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """Export an unencrypted host private key to the specified path."""
    
def export_host_chain(store: Store, host_id: str, export_path: Path) -> Result[None, str]:
    """Export a host certificate chain (host + CA certs) to the specified path."""
```

### Host Management

```python
def list_hosts(store: Store) -> Result[list[str], str]:
    """List all hosts in the store, sorted alphabetically."""
    
def host_exists(store: Store, host_id: str) -> bool:
    """Check if a host exists in the store."""
    
def ca_exists(store: Store) -> bool:
    """Check if a CA exists in the store."""
    
def delete_host(store: Store, host_id: str) -> Result[Store, str]:
    """Delete a host from the store."""
    
def get_host_info(store: Store, host_id: str) -> Result[dict[str, Any], str]:
    """Get certificate information for a host."""
```

## Implementation Strategy

The implementation will:

1. Use the `Store` dataclass from `models.py` to pass state between functions
2. Use the `Result` pattern from `result.py` for error handling
3. Implement unlock mechanisms similar to the original class design
4. Keep function parameters consistent with original methods
5. Maintain the same password handling functionality as the original class

## Migration Examples

### Original (Class-based):

```python
from pathlib import Path
from reactor_ca.store import Store, get_store

# Create a store and unlock it
store = get_store(config)
if store.unlock(password="secret"):
    # Use the store
    cert = store.load_ca_cert()
    if cert:
        store.save_host_cert("webserver", cert)
    # Change password
    store.change_password("secret", "new_secret")
```

### Refactored (Functional with Result):

```python
from pathlib import Path
from reactor_ca import store
from reactor_ca.models import Store

# Create a store and unlock it
my_store = Store(path="/path/to/store")
result = store.unlock_store(my_store, password="secret")

if result:
    unlocked_store = result.unwrap()
    
    # Use the store with method chaining for complex operations
    cert_result = store.read_ca_cert(unlocked_store)
    
    result = (
        cert_result.and_then(
            lambda cert: store.write_host_cert(unlocked_store, "webserver", cert)
        )
    )
    
    # Or with simple unwrapping for shorter operations
    if cert_result:
        cert = cert_result.unwrap()
        result = store.write_host_cert(unlocked_store, "webserver", cert)
        
    # Change password
    result = store.change_password(unlocked_store, "secret", "new_secret")
    if result:
        my_store = result.unwrap()
```

## Benefits of the Refactoring

1. **Explicit State**: State is passed as a data structure rather than maintained in a class
2. **Pure Functions**: Functions are pure and have predictable side effects
3. **Testability**: Easier to test individual functions in isolation
4. **Composability**: Functions can be easily composed together for more complex operations
5. **Type Safety**: Strong typing throughout, following project guidelines
6. **Explicit Error Handling**: Errors are represented explicitly in function signatures 

## Implementation Example

Here's a more complete example of the `unlock_store` function showing the full implementation with `Result`:

```python
def unlock_store(store: Store, password: str | None = None, ca_init: bool = False) -> Result[Store, str]:
    """Unlock the store with the provided password."""
    # If already unlocked with a password, return success
    if store.unlocked and store.password:
        return Result.success(store)
    
    # Load config for password validation
    ca_config_result = load_ca_config(store)
    if not ca_config_result:
        return Result.failure(f"Failed to load CA config: {ca_config_result.error}")
    
    ca_config = ca_config_result.unwrap()
    min_length = ca_config.password.min_length
    password_file = ca_config.password.file
    env_var = ca_config.password.env_var
    
    # Try to get password from file if specified
    if password_file and not password:
        password_result = read_password_from_file(password_file)
        if password_result:
            password = password_result.unwrap()
        
    # Try to get password from environment variable if specified
    if env_var and not password and env_var in os.environ:
        password = os.environ[env_var]
        
    # If still no password, prompt the user
    if not password:
        password = getpass("Enter CA master password: ")
        if ca_init:
            confirm = getpass("Confirm CA master password: ")
            if password != confirm:
                return Result.failure("Passwords do not match")
                
    # Validate password length
    if len(password) < min_length:
        return Result.failure(f"Password must be at least {min_length} characters long")
        
    # If in CA init mode, just store password without validation
    if ca_init:
        return Result.success(Store(
            path=store.path,
            password=password,
            unlocked=True
        ))
        
    # Validate against CA key if it exists
    ca_key_path = get_ca_key_path(store)
    if ca_key_path.exists():
        try:
            # Try to load it to verify the password
            with open(ca_key_path, "rb") as f:
                key_data = f.read()
                load_pem_private_key(key_data, password.encode("utf-8"))
            return Result.success(Store(
                path=store.path,
                password=password,
                unlocked=True
            ))
        except Exception as e:
            return Result.failure(f"Failed to unlock CA store: {str(e)}")
    else:
        # If key doesn't exist yet, store password for later use
        return Result.success(Store(
            path=store.path,
            password=password,
            unlocked=True
        ))
```

## Working with Inventory

```python
def update_inventory(store: Store) -> Result[Store, str]:
    """Update inventory based on certificate files."""
    inventory_result = read_inventory(store)
    
    # Create new inventory if we couldn't read existing one
    inventory = inventory_result.unwrap_or(Inventory(
        ca=CAInventoryEntry(
            serial="",
            not_before=datetime.datetime.now(datetime.UTC),
            not_after=datetime.datetime.now(datetime.UTC),
            fingerprint_sha256=""
        ),
        hosts=[]
    ))
    
    # Update CA info if it exists
    ca_cert_result = read_ca_cert(store)
    if ca_cert_result:
        inventory.ca = CAInventoryEntry.from_certificate(ca_cert_result.unwrap())
    
    # Update hosts
    hosts_result = list_hosts(store)
    if hosts_result:
        for host_id in hosts_result.unwrap():
            cert_result = read_host_cert(store, host_id)
            if cert_result:
                cert = cert_result.unwrap()
                # Find existing host or add new one
                for i, host in enumerate(inventory.hosts):
                    if host.short_name == host_id:
                        inventory.hosts[i] = InventoryEntry.from_certificate(host_id, cert)
                        inventory.hosts[i].renewal_count = host.renewal_count
                        inventory.hosts[i].rekey_count = host.rekey_count
                        break
                else:
                    inventory.hosts.append(InventoryEntry.from_certificate(host_id, cert))
    
    # Write updated inventory
    return write_inventory(store, inventory)
```

## Rationale for Functional Approach

The functional approach with the `Result` pattern aligns with modern Python development trends:

1. **Data orientation**: The approach focuses on data (represented by dataclasses) and operations on that data
2. **Immutability**: The pattern encourages treating data as immutable, with functions returning new copies
3. **Explicit error handling**: The `Result` pattern makes error handling explicit and consistent
4. **Testability**: Pure functions are easier to test as they depend only on their inputs
5. **Composition**: Functions with `Result` return types compose well for complex operations

By using the `Store` dataclass to maintain state between function calls and the `Result` pattern for error handling, we create a robust, maintainable, and type-safe API that can evolve with the project's needs.

This approach gives us the best of both worlds: the clarity and testability of functional programming with the familiar state management of the original design.