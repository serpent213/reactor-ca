# Installing Self-Signed Root CA Certificates

## macOS

### Command Line Installation

The most reliable method for macOS is using the `security` command:

```bash
# Install certificate to System keychain with full trust
sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain your-ca.crt

# Alternative with specific trust settings for SSL and basic validation
sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain your-ca.crt
```

### GUI Installation Method

1. Double-click the certificate file in Finder
2. Enter administrator credentials when prompted
3. Open **Keychain Access** (Applications > Utilities)
4. Locate the certificate in the System keychain
5. Double-click the certificate to open its properties
6. Expand the **Trust** section
7. Set "When using this certificate" to **Always Trust**
8. Close the dialog and enter administrator password to confirm

## Windows

### Command Line Installation

The `certutil` command provides the most straightforward installation method:

```cmd
# Install to Trusted Root Certification Authorities store
certutil -addstore -f "Root" your-ca.crt

# Verify installation
certutil -store Root
```

### PowerShell Method

```powershell
# Import certificate to Trusted Root store
Import-Certificate -FilePath ".\your-ca.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
```

### Microsoft Management Console (MMC)

For GUI-based installation:

1. Press **Windows + R**, type `mmc`, press Enter
2. Navigate to **File** > **Add/Remove Snap-ins**
3. Select **Certificates** and click **Add**
4. Choose **Computer account**, then **Next**
5. Select **Local computer** and click **Finish**
6. Expand **Certificates (Local Computer)** > **Trusted Root Certification Authorities** > **Certificates**
7. Right-click in the certificates pane, select **All Tasks** > **Import**
8. Follow the Certificate Import Wizard, placing certificates in the **Trusted Root Certification Authorities** store

## Debian/Ubuntu

### Installation Process

Debian and Ubuntu use the `ca-certificates` package for system-wide certificate management:

```bash
# Create directory for custom CA certificates
sudo mkdir -p /usr/local/share/ca-certificates/custom-ca

# Copy certificate (must have .crt extension)
sudo cp your-ca.pem /usr/local/share/ca-certificates/custom-ca/your-ca.crt

# Update certificate store
sudo update-ca-certificates
```

### Certificate Removal

```bash
# Remove certificate file
sudo rm /usr/local/share/ca-certificates/custom-ca/your-ca.crt

# Update certificate store to remove references
sudo update-ca-certificates --fresh
```

## Arch Linux

### Primary Installation Method

Arch Linux uses the p11-kit trust system for certificate management:

```bash
# Copy certificate to trust anchors directory
sudo cp your-ca.crt /etc/ca-certificates/trust-source/anchors/

# Update certificate trust store
sudo update-ca-trust

# Alternative legacy command
sudo trust extract-compat
```

### Using the trust Command

The `trust` utility provides more granular control:

```bash
# Install certificate as trusted anchor
sudo trust anchor --store your-ca.crt

# List all trusted certificates
trust list

# Remove specific certificate
sudo trust anchor --remove your-ca.crt
```

## NixOS

### Declarative Configuration

NixOS manages certificates through the system configuration:

```nix
{
  # Method 1: Reference external certificate files
  security.pki.certificateFiles = [
    /path/to/your-ca.crt
  ];

  # Method 2: Embed certificate content directly
  security.pki.certificates = [
    ''
    -----BEGIN CERTIFICATE-----
    MIICljCCAX4CCQCKNvRU...
    ... certificate content ...
    -----END CERTIFICATE-----
    ''
  ];
}
```

### Applying Configuration Changes

```bash
# Rebuild system configuration
sudo nixos-rebuild switch
```

## iOS

### Installation Process

iOS requires a two-step process for installing self-signed root CA certificates, with the second step being critical for full SSL/TLS trust.

#### Step 1: Certificate Installation

**Method 1: Email Distribution**

1. Email the certificate file (.crt, .pem, or .cer) as an attachment to the iOS device
2. Open the email attachment in the Mail app
3. Tap the certificate file to initiate installation
4. Follow the installation prompts

**Method 2: Web Download**

1. Host the certificate file on a web server
2. Open Safari and navigate to the certificate URL
3. Download the certificate file
4. The system will prompt for profile installation

**Method 3: Cloud Service Distribution**

1. Upload the certificate to iCloud, Dropbox, or similar service
2. Access the file through the respective app on iOS
3. Tap the certificate to begin installation

#### Step 2: Profile Installation Confirmation

After downloading, the certificate installation process begins:

1. Navigate to **Settings** > **General** > **VPN \& Device Management**
2. Locate the downloaded profile under "DOWNLOADED PROFILE"
3. Tap the profile name
4. Tap **Install** (you may need to enter your device passcode)
5. Review the certificate warning that states the certificate is not verified
6. Tap **Install** again to confirm
7. Tap **Install** a third time if prompted
8. The profile should show as "Verified" upon successful installation

#### Step 3: Enable Full Trust (Critical)

**This step is essential** - without it, the certificate will not be trusted for SSL/TLS connections:

1. Navigate to **Settings** > **General** > **About** > **Certificate Trust Settings**
2. Under "Enable full trust for root certificates," toggle **ON** the switch for your certificate
3. Read the security warning about third-party access to encrypted traffic
4. Tap **Continue** to confirm trust

**Note**: If "Certificate Trust Settings" doesn't appear, no additional certificates have been installed.

### iOS-Specific Considerations

**Security Warning**: iOS displays explicit warnings about unverified certificates to protect users from potential man-in-the-middle attacks. These warnings are intentional security features.

**Enterprise Deployment**: For large-scale deployments, Apple recommends using Apple Configurator or Mobile Device Management (MDM). Certificates installed via these methods are automatically trusted without requiring the manual trust step.

**Supervised Devices**: On supervised iOS devices, users cannot modify certificate trust settings - these are managed by the supervising organization.

## Android

### Installation Overview

Android certificate installation varies significantly between versions and device configurations. Modern Android versions (7+) distinguish between **user certificates** and **system certificates**, with important security implications.

#### Standard Installation (User Certificate Store)

This method works on all Android devices but provides limited trust for applications:

1. **Download Certificate**: Transfer the certificate file (.crt, .pem, .cer, or .p7b) to the device storage
2. **Access Settings**: Navigate to **Settings** > **Security** (or search for "Encryption and Credentials")
3. **Install Certificate**:
    - Tap **Encryption and Credentials** > **Install a certificate**
    - Select **CA Certificate**
    - Android will display a security warning about network monitoring
    - Tap **Install anyway**
4. **Browse and Select**: Navigate to the certificate file location and select it
5. **Provide Name**: Enter a name for the certificate when prompted
6. **Verification**: Check installation under **Settings** > **Security** > **Trusted Credentials** > **User** tab

### Android Version Differences

**Android 6 and Earlier**: User certificates had broader application trust
**Android 7-13**: User certificates only trusted by apps that explicitly opt-in
**Android 14+**: System certificate store moved to APEX containers, requiring specialized methods

#### System Certificate Installation (Android 14+)

For Android 14 and later, installing system-trusted certificates requires advanced methods due to the move to APEX (Android Pony Express) containers.

**Method 1: Magisk Module - Cert-Fixer**

The Cert-Fixer module automates system certificate installation:

1. **Root Device**: Ensure device is rooted with Magisk installed
2. **Install Module**: Download and install Cert-Fixer.zip through Magisk Manager
3. **Install User Certificate**: Follow standard user certificate installation process
4. **Reboot**: Cert-Fixer automatically copies user certificates to system store during boot
5. **Verify**: Check system certificates under **Trusted Credentials** > **System** tab

**Method 2: NCC Group ConscryptTrustUserCerts Module**

Alternative Magisk module specifically designed for Android 14:

1. Install the ConscryptTrustUserCerts module via Magisk
2. Install certificates in user store as normal
3. Module automatically integrates user certificates with Conscrypt APEX module
4. Reboot to activate changes

### Android-Specific Limitations

**Non-Rooted Devices**: System certificate installation is impossible on non-rooted devices running Android 7+. User certificates provide limited functionality for most applications.

**Google Play Store Emulators**: Official Android emulators with Google Play Store support prevent root access, requiring alternative emulator images for certificate testing.

## Troubleshooting and Verification

### Common Verification Commands

```bash
# Test HTTPS connectivity
curl -v https://your-internal-site.local

# Detailed SSL connection analysis
openssl s_client -connect your-internal-site.local:443 -CApath /etc/ssl/certs

# macOS: List keychain certificates
security find-certificate -a -p /Library/Keychains/System.keychain

# Windows: Display certificate store contents
certutil -store Root
```
