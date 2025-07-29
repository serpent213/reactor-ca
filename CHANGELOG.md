# Changelog

All notable changes to ReactorCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
