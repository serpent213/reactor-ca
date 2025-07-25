# Changelog

All notable changes to ReactorCA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0-rc] - 2025-07-25

### Changed
- Config hosts.yml []deploy.commands -> deploy.command

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
