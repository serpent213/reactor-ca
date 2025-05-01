# Dataclass Analysis for ReactorCA

## Existing Dataclasses

### `SubjectIdentity` (in utils.py)
- Well-implemented with methods to convert to/from x509.Name objects
- Used consistently in the codebase
- Provides a clean abstraction for certificate subject information

### `CertificateParams` (in host_operations.py)
- Used to encapsulate parameters for certificate creation
- Improves readability of certificate creation functions
- `create_certificate_with_params` implementation is clean and focused

## Suggested New Dataclasses

Based on analysis of the codebase, introducing these additional dataclasses would improve readability and maintainability:

### 1. `AlternativeNames`
```python
@dataclass
class AlternativeNames:
    dns: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    email: list[str] = field(default_factory=list)
    uri: list[str] = field(default_factory=list)
    directory_name: list[str] = field(default_factory=list)
    registered_id: list[str] = field(default_factory=list)
    other_name: list[str] = field(default_factory=list)
```
- Would replace dictionary structures used in `process_all_sans` and related functions
- Provides type hints and better IDE support
- Could include validation methods for each SAN type

### 2. `CertificateMetadata`
```python
@dataclass
class CertificateMetadata:
    serial: str
    not_before: str
    not_after: str
    fingerprint: str
    days_remaining: int | None = None
```
- Would formalize the certificate information extracted in various functions
- Could include helper methods for formatting and date calculations

### 3. `HostConfig`
```python
@dataclass
class HostConfig:
    name: str
    common_name: str
    organization: str | None = None
    organization_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    email: str | None = None
    alternative_names: AlternativeNames | None = None
    export: dict[str, str] | None = None
    deploy: dict[str, str] | None = None
    validity: dict[str, int] | None = None
    key_algorithm: str = "RSA2048"
```
- Would replace dictionary handling in `load_hosts_config()` and related functions
- Provides clear structure for host configuration parameters
- Could include validation methods and defaults

### 4. `CAConfig`
```python
@dataclass
class CAConfig:
    common_name: str
    organization: str
    organization_unit: str
    country: str
    state: str
    locality: str
    email: str
    key_algorithm: str
    validity: dict[str, int]
    password: dict[str, Any]
    hash_algorithm: str = "SHA256"
```
- Would formalize CA configuration currently handled through dictionaries
- Could include validation methods and configuration helpers

### 5. `InventoryEntry`
```python
@dataclass
class InventoryEntry:
    name: str
    serial: str
    not_after: str
    fingerprint: str
    renewal_count: int = 0
    rekeyed: bool = False
    days_remaining: int | None = None
```
- Would standardize inventory entries across the codebase
- Could include methods for calculating expiration and formatting

## Implementation Approach

1. Start with the most used dataclasses first (AlternativeNames and HostConfig)
2. Update functions incrementally to accept the new dataclasses
3. Add conversion methods between existing dictionary formats and dataclasses
4. Include proper validation within the dataclasses
5. Update documentation to reflect the new structures

## Benefits

- Improved code readability and maintainability
- Better type hints and IDE completion
- Centralized validation logic
- More self-documenting function signatures
- Natural conversion methods between formats (JSON, YAML, X.509 structures)