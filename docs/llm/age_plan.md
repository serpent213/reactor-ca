# Age Integration Plan: Complete PKCS#8 Replacement

## Overview

This plan outlines the complete replacement of ReactorCA's PKCS#8-based encryption system with age-based encryption. The approach eliminates all legacy support in favor of a clean, modern, config-driven architecture.

## Core Philosophy

- **Complete replacement** - No backward compatibility, no legacy cruft
- **Config-driven selection** - Users choose encryption method via configuration file
- **Identity provider pattern** - Clean separation between key acquisition and cryptographic operations
- **SSH infrastructure reuse** - Leverage existing SSH keys where possible

## Architecture Changes

### Directory Structure

Replace password-centric naming with identity-based providers:

```
internal/infra/
├── identity/           # Identity providers (age.Identity sources)
│   ├── password.go     # Scrypt-based identities  
│   ├── ssh.go          # SSH key-based identities
│   └── yubikey.go      # Hardware token identities (future)
├── crypto/
│   └── age_service.go  # Unified age encryption service
└── store/
    └── filestore.go    # Storage (unchanged logic)
```

### Configuration Schema

Single configuration file drives all encryption decisions:

```yaml
# config/ca.yaml
encryption:
  provider: "password"  # password|ssh|yubikey
  
  password:
    min_length: 12
    file: "/path/to/password"  
    env_var: "CA_PASSWORD"
  
  ssh:
    identity_file: "~/.ssh/id_ed25519"
    recipients:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@example.com"
      - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... deploy@example.com"
  
  yubikey:
    plugin_path: "/usr/local/bin/age-plugin-yubikey"
    recipients: 
      - "age1yubikey1q2w3e4r5t6y7u8i9o0p..."
```

### Domain Interface

Single identity provider interface:

```go
type IdentityProvider interface {
    // Get identity for decryption
    GetIdentity() (age.Identity, error)
    
    // Get recipients for encryption  
    GetRecipients() ([]age.Recipient, error)
    
    // Provider-specific validation
    Validate() error
}
```

## Implementation Details

### Password Provider

```go
// internal/infra/identity/password.go
type PasswordProvider struct {
    config domain.PasswordConfig
}

func (p *PasswordProvider) GetIdentity() (age.Identity, error) {
    password, err := p.getMasterPassword()
    if err != nil {
        return nil, err
    }
    return age.NewScryptIdentity(password)
}

func (p *PasswordProvider) GetRecipients() ([]age.Recipient, error) {
    password, err := p.getMasterPassword()  
    if err != nil {
        return nil, err
    }
    recipient, err := age.NewScryptRecipient(password)
    return []age.Recipient{recipient}, err
}
```

### SSH Provider

```go
// internal/infra/identity/ssh.go
type SSHProvider struct {
    config domain.SSHConfig
}

func (s *SSHProvider) GetIdentity() (age.Identity, error) {
    keyBytes, err := os.ReadFile(s.config.IdentityFile)
    if err != nil {
        return nil, err
    }
    return agessh.ParseIdentity(keyBytes)
}

func (s *SSHProvider) GetRecipients() ([]age.Recipient, error) {
    var recipients []age.Recipient
    for _, pubKey := range s.config.Recipients {
        recipient, err := agessh.ParseRecipient(pubKey)
        if err != nil {
            return nil, fmt.Errorf("invalid recipient %q: %w", pubKey, err)
        }
        recipients = append(recipients, recipient)
    }
    return recipients, nil
}
```

### Age Crypto Service

Complete replacement of PKCS#8 service:

```go
// internal/infra/crypto/age_service.go
type AgeService struct {
    identityProvider IdentityProvider
}

func (s *AgeService) EncryptPrivateKey(key crypto.PrivateKey) ([]byte, error) {
    recipients, err := s.identityProvider.GetRecipients()
    if err != nil {
        return nil, err
    }
    
    // Convert key to PEM
    keyPEM := s.privateKeyToPEM(key)
    
    // Encrypt with age
    var buf bytes.Buffer
    w, err := age.Encrypt(&buf, recipients...)
    if err != nil {
        return nil, err
    }
    
    if _, err := w.Write(keyPEM); err != nil {
        return nil, err
    }
    w.Close()
    
    return buf.Bytes(), nil
}

func (s *AgeService) DecryptPrivateKey(data []byte) (crypto.PrivateKey, error) {
    identity, err := s.identityProvider.GetIdentity()
    if err != nil {
        return nil, err
    }
    
    r, err := age.Decrypt(bytes.NewReader(data), identity)
    if err != nil {
        return nil, err
    }
    
    keyPEM, err := io.ReadAll(r)
    if err != nil {
        return nil, err
    }
    
    return s.pemToPrivateKey(keyPEM)
}
```

### Provider Factory

Configuration-driven provider instantiation:

```go
// internal/app/application.go
func (a *Application) createIdentityProvider() (IdentityProvider, error) {
    switch a.config.Encryption.Provider {
    case "password":
        return identity.NewPasswordProvider(a.config.Encryption.Password)
    case "ssh":
        return identity.NewSSHProvider(a.config.Encryption.SSH)
    case "yubikey":
        return identity.NewYubikeyProvider(a.config.Encryption.Yubikey)
    default:
        return nil, fmt.Errorf("unsupported encryption provider: %s", a.config.Encryption.Provider)
    }
}
```

## File Structure Changes

### New Store Layout

```
store/
├── ca/
│   ├── ca.crt           # CA certificate (unchanged)
│   └── ca.key.age       # Age-encrypted CA private key
├── hosts/
│   └── <host-id>/
│       ├── cert.crt     # Host certificate (unchanged)
│       └── cert.key.age # Age-encrypted host private key
└── ca.log              # Operation log (unchanged)
```

## User Experience

### Simplified CLI Flow

No encryption-related command line flags needed:

```bash
# Initialize - creates default config with password provider
./ca init

# User edits config/ca.yaml to choose encryption method
vim config/ca.yaml

# Everything else works the same
./ca ca create
./ca host issue web-server
```

### Configuration Examples

**Password-based (default):**
```yaml
encryption:
  provider: "password"
  password:
    min_length: 12
    env_var: "CA_PASSWORD"
```

**SSH key-based:**
```yaml
encryption:
  provider: "ssh"
  ssh:
    identity_file: "~/.ssh/id_ed25519"
    recipients:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@example.com"
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... backup@example.com"
```

## Migration Strategy

### For Existing Users

1. **Backup everything** - No backward compatibility
2. **Export private keys** - Extract from old PKCS#8 format before upgrade
3. **Re-initialize PKI** - Run `./ca init` with new age-based system
4. **Configure encryption method** - Edit `config/ca.yaml` to choose provider
5. **Re-import/recreate certificates** - Generate new CA and host certificates

### Breaking Changes

- **File format** - `.enc` files become `.age` files
- **Encryption method** - PKCS#8 + AES-256-GCM replaced with age
- **Configuration schema** - New encryption section in config files
- **CLI interface** - No encryption flags, configuration-driven only

## Implementation Order

1. **Add age dependency** - Update `go.mod` with `filippo.io/age`
2. **Create identity providers** - Implement password and SSH providers
3. **Replace crypto service** - Complete age-based implementation
4. **Update domain interfaces** - Remove PKCS#8-specific methods
5. **Modify application layer** - Use new identity provider pattern
6. **Update configuration parsing** - New encryption config schema
7. **Change file extensions** - `.age` instead of `.enc`
8. **Remove PKCS#8 code** - Delete `internal/infra/crypto/pkcs8/` directory
9. **Update documentation** - Migration guide and new configuration examples

## Benefits

### Code Simplification
- Remove ~500 lines of PKCS#8 code
- Single encryption library (age)
- No compatibility detection logic
- Cleaner error handling

### Security Improvements
- Modern authenticated encryption (ChaCha20-Poly1305)
- Better key derivation (scrypt vs PBKDF2)
- SSH key reuse eliminates password management entirely
- Future-proof cryptography

### Operational Benefits
- SSH infrastructure integration
- Multi-recipient support built-in
- Standard age tooling compatibility
- Plugin ecosystem access (Yubikey, TPM, etc.)

### Extensibility
- New providers implement single interface
- Configuration schema extends naturally
- No changes to application layer for new providers
- Clean separation of concerns

## Future Extensions

### Hardware Token Support

```go
// internal/infra/identity/yubikey.go
type YubikeyProvider struct {
    config domain.YubikeyConfig
    plugin *age.Plugin
}

func (y *YubikeyProvider) GetIdentity() (age.Identity, error) {
    return y.plugin.NewIdentity(y.config.SerialNumber)
}
```

### Plugin Architecture

The identity provider pattern naturally extends to support age's plugin ecosystem:
- **age-plugin-yubikey** - Hardware token support
- **age-plugin-tpm** - TPM 2.0 integration
- **age-plugin-se** - Apple Secure Enclave support

Each plugin can be implemented as a new identity provider without changes to the core architecture.