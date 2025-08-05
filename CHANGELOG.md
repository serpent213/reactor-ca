# Changelog

All notable changes to ReactorCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.2] - 2025-08-05

### Fixed
- **Configuration formatting**: Fixed stray TAB character in `init` default config template
- **Password environment variable**: Harmonized `REACTOR_CA_PASSWORD` config and fallback handling
- **YAML validation errors**: Show YAML filename when validation errors occur

### Changed
- **Windows deployment**: Deploy commands now run in PowerShell instead of Bash on Windows

## [1.0.0-rc.1] - 2025-08-04

### Added
- **Host rename command**: New `ca host rename` command for renaming host IDs
- **Broken/missing cert & key detection**: Automatic detection and display of corrupted certs and age key files in host list
- **Locale-aware formatting**: Internationalized date/time formatting for certificate info

### Changed
- **Host list display**: Refined table formatting
- **Certificate info output**: Cleaner formatting for certificate info
- **UI improvements**: Updated error symbols and table colors

## [0.5.0] - 2025-08-01

### Added
- **X.509 extensions**: Full support for certificate extensions (Key Usage, Basic Constraints, CRL Distribution Points, etc.)
- **CA export-key command**: New `ca export-key` command for exporting CA private keys
- **Browser compatibility testing**: Comprehensive browser testing with Chrome, Firefox, Safari across multiple certificate algorithms
- **Cross-platform testing**: Windows and macOS CI test runners
- **Runtime schema validation**: JSON schema validation of configuration files at runtime
- **OpenSSL integration**: `--openssl` flag for certificate info commands to show OpenSSL-compatible output

### Changed
- **Subject fields**: Empty subject name fields now properly set to nil
  - `organization_unit` renamed to `organizational_unit`, config migration required!
- **JSON schema library**: Migrated to santhosh-tekuri/jsonschema for better validation
- **Schema strictness**: Added `additionalProperties: false` for stricter YAML validation
- **Certificate extensions**: Extensions now displayed in certificate info output
- **Deploy variable substitution**: Added `${key_encrypted}` variable for deploy scripts
- **Algorithm names**: Support for lowercase algorithm names in configuration
- **Days calculation**: Improved calendar days calculations and rounding in certificate info
- **Path resolution**: Enhanced path resolution with `~` support in export paths
- **Console output**: Better status and error message formatting
- **Build versioning**: Version string now includes Git commit information

### Fixed
- **Key type validation**: Proper validation for host certificate key types
- **Path length constraints**: Auto-detection instead of explicit `path_length_zero` configuration
- **Schema validation**: Corrected YAML and JSON schema definitions
- **CA key usage**: Restricted key usage appropriately for CA certificates
- **Cross-platform compatibility**: PTY shell support ported to Windows
- **Certificate validation**: Stricter validation for CA import operations

### Improved
- **Documentation**: Enhanced README with TOC, examples, and browser compatibility matrix
- **Test coverage**: Expanded e2e and integration test suites
- **Build system**: Improved cross-compilation and schema validation processes
- **Error messages**: Better schema validation error reporting

## [0.4.0] - 2025-07-28

### Added
- **Additional recipients**: Support for multiple age recipients per host certificate for shared access and deployment
- **SSH key auto-detection**: Automatic SSH public key detection and configuration during `ca init`
- **JSON schemas**: YAML configuration validation with JSON schemas
- **Coverage reports**: Test coverage tracking and reporting
- **FreeBSD support**: Added FreeBSD build target
- **Encrypted key export**: Option to export private keys in encrypted format
- **Nix flake**: Flake-based package

### Changed
- **CommonName handling**: Made CommonName optional in certificate subject, following modern PKI practices
- **Deploy commands**: Simplified from array to single multi-line string format
- **Console output**: Improved styling, table rendering, and progress indicators
- **Certificate validation**: Stricter validation for CA import operations
- **Host listing**: Added algorithm information and orphaned certificate detection
- **Expiration warnings**: Unified expiration warning system with configurable thresholds
- **Time units**: Added support for "months" in validity configuration
- **SAN display**: Enhanced Subject Alternative Name presentation in certificate info
- **Re-encryption**: Improved backup/rollback system using .bak files instead of .zip archives
- **Password caching**: Enhanced password and decrypted file caching mechanisms
- **Deploy execution**: Full PTY shell support for deployment commands
- **Log timestamps**: Local timezone timestamps in log files

### Fixed
- **Certificate inheritance**: Proper host certificate data inheritance and signature selection
- **Additional recipients validation**: Only validate additional recipients when specified
- **Core dumps**: Disabled core dumps for enhanced security
- **Command replacement**: Replaced deprecated `ca passwd` with `ca reencrypt` command

### Improved
- **Round-trip validation**: Age encryption validation before CA creation
- **Test coverage**: Expanded unit, integration, and e2e test suites
- **Documentation**: Enhanced README, usage examples, and development guides
- **Build system**: Automated dependency updates and flake.nix integration

## [0.3.0] - 2025-07-23

Breaking change!

### Added
- **age-based encryption**: Complete replacement of PKCS#8 with age encryption for private key storage
- **SSH identity support**: Support for age-ssh identities for key encryption
- **Plugin system**: Support for age plugins including secure enclave and YubiKey integration
- **Example configurations**: Added example configs for secure enclave and YubiKey setups

### Changed
- **Build system**: Updated to use Go 1.24 module tools, YAML formatting

### Removed
- **PKCS#8 implementation**: Removed legacy PKCS#8 encryption code and tests
- **Stale password config**: Dropped legacy password configuration options

## [0.2.0] - 2025-07-23

- Rewrite in Go

## [0.1.0] - 2025-05-03

- Prototype in Python
