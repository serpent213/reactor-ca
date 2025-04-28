# Implementation Plan for reactorCA

## 1. Project Setup
1. Confirm Poetry is properly set up in the Nix DevEnv
2. Create initial project structure
3. Define required dependencies in `pyproject.toml`:
   - `click` for CLI options
   - `cryptography` for X.509 operations
   - `pyyaml` for host configuration
   - `rich` or `tabulate` for displaying cert information
   - `gitpython` for Git operations

## 2. Configuration Files Design
1. Design CA configuration YAML format with parameters:
   - Organization details
   - Contact information
   - Key parameters (algorithm, size)
   - Validity period
   - Password handling options
2. Design hosts configuration YAML format:
   - Common name
   - Alternative names (DNS/IP)
   - Destination path for certificates
   - Optional key parameters

## 3. Core Functionality
1. Implement key encryption/decryption functionality
   - Use modern encryption standards for private keys
   - Implement password prompt and caching
2. Implement CA initialization
   - Generate CA private key with encryption
   - Generate self-signed CA certificate
   - Save configuration
3. Implement certificate operations
   - Certificate generation with proper SAN support
   - Certificate renewal logic
   - CSR handling for existing private keys

## 4. CLI Interface
1. Create main entry point with Click framework
2. Implement commands:
   - `--init`: Generate new CA
   - `--generate`: Generate host certificate
   - `--renew`: Renew specific certificate 
   - `--renew-all`: Renew all certificates
   - `--list`: Display certificate inventory
   - `--commit`: Commit changes to Git
   - `--import-key`: Import existing private key
   - `--passwd`: Ask for old and new password (with confirmation) and reencrypt all secrets

## 5. Certificate Management
1. Design certificate tracking method:
   - Use stateless approach
   - Implement serial number management (use random numbers)
   - Track validity periods
2. Implement certificate inventory system
   - Store metadata for easy listing
   - Support filtering and sorting

## 6. Git Integration
1. Implement Git operations
   - Track and stage certificate changes
   - Create meaningful commit messages
   - Avoid committing sensitive data

## 7. Testing
1. Create comprehensive test suite
   - Unit tests for cryptography operations
   - CLI interface tests
   - Configuration file parsing tests
   - Error handling tests

## 8. Documentation
1. Create user documentation:
   - Installation instructions
   - Usage examples
   - Configuration reference
   - Security best practices
2. Add inline code documentation

## 9. Security Considerations
1. Ensure proper handling of private keys
2. Implement secure password management
3. Apply X.509 best practices
4. Validate all user input
