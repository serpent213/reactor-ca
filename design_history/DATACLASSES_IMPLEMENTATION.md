# ReactorCA Dataclass Implementation

This document details the implementation of dataclasses in the ReactorCA project to improve readability and maintainability.

## Added Dataclasses

The following dataclasses have been created in the new `models.py` file:

### Core Certificate Dataclasses
- `SubjectIdentity` - Certificate subject information
- `CertificateParams` - Parameters for certificate creation
- `CertificateMetadata` - Certificate metadata (serial, validity dates, fingerprint)
- `CSRInfo` - Information extracted from certificate signing requests

### Configuration Dataclasses
- `AlternativeNames` - Subject Alternative Names management
- `ValidityConfig` - Certificate validity period configuration
- `PasswordConfig` - CA password configuration
- `HostConfig` - Host certificate configuration
- `CAConfig` - CA configuration
- `ExportConfig` - Certificate export configuration
- `DeploymentConfig` - Certificate deployment configuration

### Inventory Dataclasses
- `InventoryEntry` - Entry in the certificate inventory
- `CAInventoryEntry` - CA entry in the certificate inventory

## Implementation Details

The implementation focuses on a lightweight, type-safe approach:

- Clean dataclass definitions with minimal methods
- Strong typing with Python's type hints
- No unnecessary conversion methods
- Direct usage of dataclasses in function signatures

### Modified Functions

Several key functions were updated to use these dataclasses:

1. `calculate_validity_days` - Now accepts a `ValidityConfig` object
2. `create_subject_from_config` - Now accepts a `HostConfig` object
3. `process_all_sans` - Now accepts an `AlternativeNames` object
4. `extract_sans_from_csr` - Now returns an `AlternativeNames` object
5. `create_certificate` - Updated parameter types to use dataclasses

## Benefits

The use of dataclasses provides several benefits:

1. **Type Safety** - Better type hints and IDE autocompletion
2. **Clean Code** - Minimal boilerplate for data structures
3. **Documentation** - Self-documenting code with clear attribute definitions
4. **Maintainability** - More structured code with consistent attribute access
5. **Lightweight** - No unnecessary conversion methods

## Future Improvements

Further refactoring could include:

1. Updating more functions to use these dataclasses natively
2. Adding validation methods to dataclasses
3. Using dataclasses in CLI interface parsing
4. Further refinement of dataclass relationships