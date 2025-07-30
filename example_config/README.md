# Example Configuration

This directory contains example configuration files for ReactorCA. These files serve as reference examples and should not be used directly in your ReactorCA installation.

## Usage

To set up your own configuration, initialize a new ReactorCA instance:

```bash
ca init
```

This will create the necessary configuration files in the `config` directory with default values.

## Files

### Basic Configuration
- **ca.yaml**: Standard Certificate Authority configuration with password-based encryption
- **hosts.yaml**: Host certificate definitions

### Hardware Security Examples
- **ca-secure-enclave.yaml**: CA configuration using Apple Secure Enclave (Touch ID/Face ID)
- **ca-yubikey.yaml**: CA configuration using YubiKey hardware token

## Encryption Providers

ReactorCA supports multiple encryption providers for protecting private keys:

### Password (Default)
Uses age scrypt-based encryption with a master password:
```yaml
encryption:
  provider: password
  password:
    min_length: 12
    env_var: REACTOR_CA_PASSWORD
```

### SSH Keys
Uses existing SSH keys with age-ssh:
```yaml
encryption:
  provider: ssh
  ssh:
    identity_file: "~/.ssh/id_ed25519"
    recipients:
      - "ssh-ed25519 AAAAC3..."
```

### Age Plugins
Uses any age plugin (secure-enclave, yubikey, tpm, etc.):
```yaml
encryption:
  provider: plugin
  plugin:
    identity_file: "~/.age/plugin-identity.txt"
    recipients:
      - "age1se1q..."  # Secure Enclave
      - "age1yubikey1q..."  # YubiKey
```

## Hardware Security Setup

### Apple Secure Enclave
Requires macOS with Secure Enclave processor:
```bash
# Install plugin
brew install age-plugin-se

# Generate identity with Touch ID requirement
age-plugin-se keygen --access-control=any-biometry -o ~/.age/se-identity.txt

# Use ca-secure-enclave.yaml as template
```

### YubiKey
Requires YubiKey 4+ with PIV support:
```bash
# Install plugin (download from GitHub releases)
# Generate and configure YubiKey identity
age-plugin-yubikey --generate

# Use ca-yubikey.yaml as template
```

## Customization

After running `init`, customize the generated configuration files in the `config` directory to match your requirements. Copy and modify the example files as needed.
