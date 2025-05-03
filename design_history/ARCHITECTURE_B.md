# Functional Python Architecture

This document outlines a modern, functional architecture for Python 3.12 applications, focusing on immutable dataclasses and functional programming principles.

## Core Principles

- **Immutability**: All data structures are immutable to prevent side effects
- **Pure Functions**: Functions have no side effects and return the same output for the same input
- **Function Composition**: Build complex operations from simple, composable functions
- **Type Safety**: Leverage Python's type system for clarity and correctness

## Directory Structure Options

### Domain-Driven Structure

```
myapp/
├── domain/                # Core domain models and operations
│   ├── models.py          # Immutable dataclasses
│   └── operations.py      # Pure functions operating on models
├── adapters/              # Adapters for external systems
│   ├── persistence.py     # Functions for data storage
│   └── services.py        # External service interfaces
├── ports/                 # Entry points to the application
│   ├── cli.py             # Command line interface
│   └── api.py             # API endpoints
└── infrastructure/        # Technical concerns
    ├── config.py          # Configuration management
    └── logging.py         # Logging infrastructure
```

### Pipeline-Based Structure

```
myapp/
├── models/                # Domain data models
│   └── domain_models.py   # Immutable dataclasses
├── transformations/       # Pure transformation functions
│   ├── validation.py      # Input validation
│   └── conversion.py      # Data type conversions
├── operations/            # Operational functions
│   ├── read_ops.py        # Read operations (queries)
│   └── write_ops.py       # Write operations (commands)
├── io/                    # Input/output handling
│   ├── readers.py         # Functions to read from external sources
│   └── writers.py         # Functions to write to external targets
└── entrypoints/           # Application entry points
    └── cli.py             # Command line interface
```

### Feature-Based Structure

```
myapp/
├── core/                  # Shared core functionality
│   ├── models.py          # Common data models
│   └── errors.py          # Error types and handling
├── feature1/              # First feature module
│   ├── models.py          # Feature-specific models
│   └── operations.py      # Feature operations
├── feature2/              # Second feature module
│   ├── models.py          # Feature-specific models
│   └── operations.py      # Feature operations
└── infrastructure/        # Technical concerns
    └── config.py          # Configuration handling
```

## Data Models

Immutable dataclasses form the foundation:

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet

@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    valid_from: datetime
    valid_until: datetime
    serial_number: str
    alternative_names: FrozenSet[str] = field(default_factory=frozenset)
    
    def __post_init__(self) -> None:
        if self.valid_from >= self.valid_until:
            raise ValueError("Valid from date must be before valid until date")

@dataclass(frozen=True)
class PrivateKey:
    key_id: str
    algorithm: str
    key_size: int
    encrypted_data: bytes
    
@dataclass(frozen=True)
class CertificateWithKey:
    certificate: Certificate
    key: PrivateKey
```

## Function Organization

Organize functions to maximize composability:

```python
from typing import Callable, List, TypeVar
from functools import reduce

T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')

# Function composition
def compose(f: Callable[[U], V], g: Callable[[T], U]) -> Callable[[T], V]:
    """Compose two functions: f(g(x))."""
    return lambda x: f(g(x))

# Pipeline multiple functions
def pipeline(*functions: Callable) -> Callable:
    """Create a pipeline of functions applied in sequence."""
    return reduce(compose, functions)

# Higher-order function example
def filter_map(predicate: Callable[[T], bool], 
               transform: Callable[[T], U]) -> Callable[[List[T]], List[U]]:
    """Filter items by predicate then apply transformation."""
    return lambda items: [transform(item) for item in items if predicate(item)]
```

## Error Handling

Use a functional approach to error handling:

```python
from dataclasses import dataclass
from typing import Generic, TypeVar, Union, Callable

T = TypeVar('T')
E = TypeVar('E')
R = TypeVar('R')

@dataclass(frozen=True)
class Success(Generic[T]):
    value: T

@dataclass(frozen=True)
class Failure(Generic[E]):
    error: E

Result = Union[Success[T], Failure[E]]

def bind(f: Callable[[T], Result[R, E]], result: Result[T, E]) -> Result[R, E]:
    """Chain operations that might fail."""
    if isinstance(result, Success):
        return f(result.value)
    return result
```

## CA Specific Example

A functional approach for certificate operations:

```python
def create_certificate(request: CertificateRequest, 
                      ca_config: CAConfig) -> Result[CertificateWithKey, str]:
    """Create a certificate based on a request."""
    # Generate key
    key_result = generate_key(request.key_size)
    if isinstance(key_result, Failure):
        return key_result
        
    # Create certificate
    cert_result = issue_certificate(
        request, 
        ca_config, 
        key_result.value
    )
    
    if isinstance(cert_result, Failure):
        return cert_result
        
    # Return certificate with key
    return Success(CertificateWithKey(
        certificate=cert_result.value,
        key=key_result.value
    ))

# Usage:
result = create_certificate(request, ca_config)
if isinstance(result, Success):
    store_certificate(result.value.certificate)
    store_key(result.value.key)
else:
    handle_error(result.error)
```

This architecture provides a foundation for building functional Python applications with immutability, composability, and type safety - particularly suitable for CA systems where correctness and reliability are critical.