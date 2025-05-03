# Functional Architecture for ReactorCA

This document outlines a modern, functional architecture for Python 3.12+ applications, with a focus on immutability and functional programming principles while maintaining readability for senior Python developers.

## Core Principles

1. **Immutability First**: Use frozen dataclasses for all data models to prevent unexpected mutations
2. **Pure Functions**: Functions should have no side effects and return consistent results for the same inputs
3. **Function Composition**: Build complex behavior by composing simple functions
4. **Type Safety**: Leverage Python's type system for safer code and better developer experience
5. **Domain-Driven Design**: Structure code around the business domain of certificate management
6. **Explicit Error Handling**: Use return values instead of exceptions for expected error conditions

## Directory Structure

We'll use a domain-driven structure that clearly separates concerns:

```
reactor_ca/
├── __init__.py
├── domain/                  # Domain models as immutable dataclasses
│   ├── __init__.py
│   └── models.py            # Core domain entities
├── operations/              # Pure functions implementing business logic
│   ├── __init__.py
│   ├── ca_operations.py     # CA certificate operations
│   └── host_operations.py   # Host certificate operations
├── adapters/                # Adapters to external systems
│   ├── __init__.py
│   ├── store.py             # Data storage functions
│   └── crypto_adapter.py    # Interface to cryptography library
├── ports/                   # Application ports (CLI)
│   ├── __init__.py
│   └── cli.py               # Command-line interface
├── schemas/                 # Configuration schemas
│   ├── __init__.py
│   ├── ca_config_schema.yaml
│   └── hosts_config_schema.yaml
└── utils/                   # Cross-cutting concerns
    ├── __init__.py
    ├── result.py            # Result type for functional error handling
    ├── config.py            # Configuration handling
    └── paths.py             # Path utilities
```

## Domain Models with Immutable Dataclasses

The core of our application is built on immutable dataclasses representing our domain:

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet, Optional

@dataclass(frozen=True)
class CAConfig:
    """Immutable CA configuration."""
    organization: str
    common_name: str
    validity_days: int = 3650
    key_size: int = 4096

@dataclass(frozen=True)
class PrivateKey:
    """Immutable private key representation."""
    key_data: bytes
    key_type: str
    is_encrypted: bool

@dataclass(frozen=True)
class Certificate:
    """Certificate domain model."""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    alt_names: FrozenSet[str] = field(default_factory=frozenset)
    
    @property
    def is_valid(self: "Certificate") -> bool:
        """Check if certificate is currently valid."""
        now = datetime.now()
        return self.not_before <= now <= self.not_after

@dataclass(frozen=True)
class CertificateWithKey:
    """Certificate with its private key."""
    certificate: Certificate
    key: PrivateKey
```

## Practical Error Handling with Result Type

Use a simple Result type to handle errors without overly complex monadic operations:

```python
from dataclasses import dataclass
from typing import Generic, TypeVar, Union, Callable, cast

T = TypeVar('T')  # Success type
E = TypeVar('E')  # Error type

@dataclass(frozen=True)
class Success(Generic[T]):
    """Represents a successful operation with a value."""
    value: T

@dataclass(frozen=True)
class Failure(Generic[E]):
    """Represents a failed operation with an error."""
    error: E

Result = Union[Success[T], Failure[E]]

# Helper function to chain operations that might fail
def bind(result: Result[T, E], f: Callable[[T], Result[R, E]]) -> Result[R, E]:
    """Chain operations that return Result (simplified monadic bind)."""
    if isinstance(result, Success):
        return f(result.value)
    return cast(Failure[E], result)
```

## Function Composition

Implement simple function composition utilities that are intuitive and practical:

```python
from functools import reduce
from typing import Callable, TypeVar, Any, List

A = TypeVar('A')
B = TypeVar('B')
C = TypeVar('C')

def compose(f: Callable[[B], C], g: Callable[[A], B]) -> Callable[[A], C]:
    """Compose two functions: f(g(x))."""
    return lambda x: f(g(x))

def pipe(value: A, *functions: Callable) -> Any:
    """Pipe a value through a series of functions."""
    return reduce(lambda acc, f: f(acc), functions, value)
```

## CA Operations Implementation Example

Here's how we would implement certificate operations:

```python
# operations/ca_operations.py
from typing import Callable
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from cryptography.hazmat.primitives import serialization

from domain.models import CAConfig, PrivateKey, Certificate, CertificateWithKey
from utils.result import Result, Success, Failure, bind

def generate_private_key(
    key_size: int,
    password_provider: Callable[[], bytes]
) -> Result[PrivateKey, str]:
    """Generate a new RSA private key."""
    try:
        # Generate key with cryptography library
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Encrypt the key
        encrypted_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password_provider()
            )
        )
        
        # Return immutable representation
        return Success(PrivateKey(
            key_data=encrypted_key,
            key_type="RSA",
            is_encrypted=True
        ))
    except Exception as e:
        return Failure(f"Failed to generate private key: {str(e)}")

def create_ca_certificate(
    config: CAConfig, 
    key: PrivateKey,
    password_provider: Callable[[], bytes]
) -> Result[Certificate, str]:
    """Create a new CA certificate using provided key."""
    # Implementation would use cryptography library
    # and return a Result[Certificate, str]
    ...

def issue_ca(
    config: CAConfig,
    password_provider: Callable[[], bytes]
) -> Result[CertificateWithKey, str]:
    """Issue a new CA certificate with key."""
    # Generate key first
    key_result = generate_private_key(config.key_size, password_provider)
    
    # Use bind to chain operations that might fail
    cert_result = bind(key_result, lambda key: 
        create_ca_certificate(config, key, password_provider)
    )
    
    # Combine results if successful
    if isinstance(cert_result, Success):
        return Success(CertificateWithKey(
            certificate=cert_result.value,
            key=key_result.value  # Safe because bind only succeeds if key_result is Success
        ))
    return cert_result  # Return the failure
```

## CLI Interface

The CLI interface uses the functional core but handles side effects at the edge:

```python
# ports/cli.py
import click
from pathlib import Path
from operations import ca_operations
from domain.models import CAConfig
from adapters import store
from utils.result import Success, Failure

@click.group()
def ca():
    """CA management commands."""
    pass

@ca.command("issue")
@click.option("--org", required=True, help="Organization name")
@click.option("--cn", required=True, help="Common Name")
@click.option("--days", default=3650, help="Validity in days")
@click.option("--keysize", default=4096, help="RSA key size")
def issue_ca(org: str, cn: str, days: int, keysize: int):
    """Issue a new CA certificate."""
    # Create immutable config
    config = CAConfig(
        organization=org,
        common_name=cn,
        validity_days=days,
        key_size=keysize
    )
    
    # Get password from user (side effect at the edge)
    def get_password() -> bytes:
        return click.prompt("Enter encryption password", 
                         hide_input=True).encode()
    
    # Call pure function
    result = ca_operations.issue_ca(config, get_password)
    
    # Handle result with pattern matching (Python 3.10+)
    match result:
        case Success(ca_with_key):
            # Store certificate and key (side effects at the edge)
            store_result = store.save_certificate_and_key(ca_with_key)
            match store_result:
                case Success(path):
                    click.echo(f"CA created successfully at {path}")
                case Failure(error):
                    click.echo(f"Error saving CA: {error}", err=True)
        case Failure(error):
            click.echo(f"Error: {error}", err=True)
```

## Testing Pure Functions

Pure functions with explicit inputs and outputs are easier to test:

```python
# tests/test_ca_operations.py
from datetime import datetime, timedelta
import pytest
from freezegun import freeze_time

from domain.models import CAConfig, PrivateKey
from operations import ca_operations
from utils.result import Success, Failure

def test_generate_private_key():
    # Arrange
    key_size = 2048  # Smaller key for faster tests
    password = lambda: b"test-password"
    
    # Act
    result = ca_operations.generate_private_key(key_size, password)
    
    # Assert
    assert isinstance(result, Success)
    assert result.value.key_type == "RSA"
    assert result.value.is_encrypted is True

@freeze_time("2023-01-01")
def test_create_ca_certificate():
    # Arrange
    config = CAConfig(
        organization="Test Org",
        common_name="Test CA",
        validity_days=365,
        key_size=2048
    )
    # Setup test key
    key = PrivateKey(key_data=b"...", key_type="RSA", is_encrypted=True)
    password = lambda: b"test-password"
    
    # Act 
    result = ca_operations.create_ca_certificate(config, key, password)
    
    # Assert
    assert isinstance(result, Success)
    assert result.value.subject == "CN=Test CA,O=Test Org"
    assert result.value.not_before == datetime(2023, 1, 1)
    assert result.value.not_after == datetime(2023, 1, 1) + timedelta(days=365)
```

## Benefits of this Architecture

1. **Improved Testability**: Pure functions with explicit inputs and outputs are easier to test
2. **Better Maintainability**: Clear separation of concerns with explicit data flow
3. **Composability**: Building complex operations from simpler ones
4. **Type Safety**: Leveraging Python's type system for better developer experience
5. **Explicit Error Handling**: No hidden exceptions, clear error paths
6. **Simpler Reasoning**: Easier to understand code without hidden side effects
7. **Practical Functional Programming**: Using FP principles without overwhelming complexity

## Implementation Guidelines

1. **Prefer immutability** but don't overengineer - use `@dataclass(frozen=True)` where it matters
2. **Keep functions pure** but allow controlled side effects at the edges of the system
3. **Use the Result type** for error handling but avoid excessive monad transformations
4. **Leverage type hints** throughout the codebase for better tooling support
5. **Write small, focused functions** that do one thing well
6. **Compose functions** to build more complex operations
7. **Test aggressively** - pure functions are easier to test
8. **Keep state changes explicit** - make data flow visible
9. **Separate pure core from impure shell** - isolate side effects