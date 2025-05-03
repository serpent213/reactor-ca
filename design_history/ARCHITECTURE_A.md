# Functional Architecture for Modern Python 3.12 Applications

This document outlines an architecture for Python 3.12 applications using a strictly functional approach with immutable dataclasses.

## Core Principles

1. **Immutability First**: Use frozen dataclasses for all data models
2. **Pure Functions**: Functions should have no side effects and return consistent results for the same inputs
3. **Function Composition**: Build complex behavior by composing simple functions
4. **Type Safety**: Leverage Python's type system for safer code
5. **Domain Driven Design**: Structure code around the business domain
6. **Railway-Oriented Programming**: Handle errors functionally with Either/Result types

## Directory Structure

```
app_name/
├── __init__.py
├── domain/                  # Domain models as immutable dataclasses
│   ├── __init__.py
│   └── models.py            # Core domain entities
├── schemas/                 # Input/output schemas for validation
│   ├── __init__.py
│   └── validators.py
├── config/                  # Configuration handling
│   ├── __init__.py
│   └── settings.py
├── operations/              # Pure functions implementing business logic
│   ├── __init__.py
│   └── <domain>_ops.py      # Domain-specific operations
├── adapters/                # Adapters to external systems
│   ├── __init__.py
│   ├── repositories.py      # Data access functions
│   └── services.py          # External service adapters
├── ports/                   # Application ports (CLI, API, etc.)
│   ├── __init__.py
│   ├── cli.py
│   └── api.py
└── common/                  # Cross-cutting concerns
    ├── __init__.py
    ├── result.py            # Result/Either type implementations
    ├── fp.py                # Functional programming utilities
    └── types.py             # Custom types and type aliases
```

## Domain Models with Immutable Dataclasses

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet, Optional

@dataclass(frozen=True)
class Certificate:
    """Certificate domain model."""
    subject: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    issuer: str
    alt_names: FrozenSet[str] = field(default_factory=frozenset)
    
    @property
    def is_valid(self: "Certificate") -> bool:
        """Check if certificate is currently valid."""
        now = datetime.now()
        return self.not_before <= now <= self.not_after

# Create a new certificate with a different expiration (immutable)
def extend_certificate(cert: Certificate, new_not_after: datetime) -> Certificate:
    """Return a new certificate with an updated expiration date."""
    return Certificate(
        subject=cert.subject,
        not_before=cert.not_before,
        not_after=new_not_after,
        serial_number=cert.serial_number,
        issuer=cert.issuer,
        alt_names=cert.alt_names
    )
```

## Result Type for Railway-Oriented Programming

```python
from dataclasses import dataclass
from typing import Generic, TypeVar, Union, Callable, cast

T = TypeVar('T')
E = TypeVar('E')

@dataclass(frozen=True)
class Success(Generic[T]):
    """Represents a successful operation with a value."""
    value: T
    
    def map(self: "Success[T]", f: Callable[[T], T]) -> "Success[T]":
        """Apply function to the value and return new Success."""
        return Success(f(self.value))
    
    def and_then(self: "Success[T]", f: Callable[[T], "Result[T, E]"]) -> "Result[T, E]":
        """Chain operations that also return Result."""
        return f(self.value)
    
    def unwrap(self: "Success[T]") -> T:
        """Get the value."""
        return self.value
    
    def unwrap_or(self: "Success[T]", default: T) -> T:
        """Get the value or default."""
        return self.value

@dataclass(frozen=True)
class Failure(Generic[E]):
    """Represents a failed operation with an error."""
    error: E
    
    def map(self: "Failure[E]", f: Callable[[T], T]) -> "Failure[E]":
        """No-op for failures."""
        return self
    
    def and_then(self: "Failure[E]", f: Callable[[T], "Result[T, E]"]) -> "Failure[E]":
        """No-op for failures."""
        return self
    
    def unwrap(self: "Failure[E]") -> T:
        """Raise exception."""
        raise ValueError(f"Cannot unwrap Failure: {self.error}")
    
    def unwrap_or(self: "Failure[E]", default: T) -> T:
        """Return the default value."""
        return default

Result = Union[Success[T], Failure[E]]
```

## Function Composition

```python
from functools import reduce
from typing import Callable, TypeVar, List

A = TypeVar('A')
B = TypeVar('B')
C = TypeVar('C')

def compose(f: Callable[[B], C], g: Callable[[A], B]) -> Callable[[A], C]:
    """Compose two functions: f ∘ g."""
    return lambda x: f(g(x))

def pipe(value: A, *funcs: Callable) -> Any:
    """Pipe a value through a series of functions."""
    return reduce(lambda acc, f: f(acc), funcs, value)
```

## CA Example Implementation

```python
# domain/models.py
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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
class CACertificate:
    """Immutable CA certificate."""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    key: PrivateKey

# operations/ca_ops.py
from pathlib import Path
from typing import Callable
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from cryptography.hazmat.primitives import serialization

from domain.models import CAConfig, PrivateKey, CACertificate
from common.result import Result, Success, Failure

def generate_private_key(
    key_size: int,
    password_provider: Callable[[], bytes]
) -> Result[PrivateKey, str]:
    """Generate a new RSA private key."""
    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        encrypted_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password_provider()
            )
        )
        
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
) -> Result[CACertificate, str]:
    """Create a new CA certificate."""
    # Implementation omitted for brevity
    ...

# adapters/repositories.py
from pathlib import Path
from typing import Optional
from domain.models import PrivateKey, CACertificate
from common.result import Result, Success, Failure

def save_private_key(key: PrivateKey, path: Path) -> Result[Path, str]:
    """Save private key to filesystem."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(key.key_data)
        return Success(path)
    except Exception as e:
        return Failure(f"Failed to save private key: {str(e)}")

# ports/cli.py
import click
from pathlib import Path
from operations import ca_ops
from domain.models import CAConfig
from adapters import repositories

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
    config = CAConfig(
        organization=org,
        common_name=cn,
        validity_days=days,
        key_size=keysize
    )
    
    # Get password from user
    def get_password() -> bytes:
        return click.prompt("Enter encryption password", 
                          hide_input=True).encode()
    
    # Generate key and certificate
    key_result = ca_ops.generate_private_key(config.key_size, get_password)
    
    # Handle errors with railway programming
    ca_cert_result = key_result.and_then(
        lambda key: ca_ops.create_ca_certificate(config, key, get_password)
    )
    
    # Save results with proper error handling
    result = ca_cert_result.and_then(
        lambda cert: repositories.save_certificate_and_key(cert)
    )
    
    if isinstance(result, Success):
        click.echo(f"CA created successfully at {result.value}")
    else:
        click.echo(f"Error: {result.error}", err=True)
```

## Testing Functional Code

```python
# tests/test_ca_ops.py
from datetime import datetime, timedelta
import pytest
from freezegun import freeze_time

from domain.models import CAConfig, PrivateKey
from operations import ca_ops
from common.result import Success, Failure

def test_generate_private_key():
    # Arrange
    key_size = 2048  # Smaller key for faster tests
    password = lambda: b"test-password"
    
    # Act
    result = ca_ops.generate_private_key(key_size, password)
    
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
    # Setup PrivateKey with test data
    key = PrivateKey(key_data=b"...", key_type="RSA", is_encrypted=True)
    password = lambda: b"test-password"
    
    # Act 
    result = ca_ops.create_ca_certificate(config, key, password)
    
    # Assert
    assert isinstance(result, Success)
    assert result.value.subject == "CN=Test CA,O=Test Org"
    assert result.value.not_before == datetime(2023, 1, 1)
    assert result.value.not_after == datetime(2023, 1, 1) + timedelta(days=365)
```

## Benefits of this Architecture

1. **Testability**: Pure functions are easier to test
2. **Maintainability**: Separation of concerns with clear boundaries
3. **Composability**: Building complex operations from simpler ones
4. **Type Safety**: Better error detection at development time
5. **Resilience**: Explicit error handling with Result types
6. **Reasoning**: Easier to reason about code without side effects

## Further Enhancements

1. **Pattern Matching** (Python 3.10+): Use structural pattern matching for more elegant data transformations
2. **Partial Application**: Implement a `partial` utility for more flexible function composition
3. **Monadic Operations**: Add more monadic operators like `map_error`, `fold`, etc.
4. **Validated Type**: Implement accumulating validation errors using Applicative pattern
5. **Dependency Injection**: Use closures and higher-order functions for dependency injection