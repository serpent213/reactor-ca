# Example Configuration

This directory contains example configuration files for ReactorCA. These files serve as reference examples and should not be used directly in your ReactorCA installation.

## Usage

To set up your own configuration, initialize a new ReactorCA instance:

```bash
ca init
```

This will create the necessary configuration files in the `config` directory with default values.

## Files

- **ca.yaml**: Configuration for your Certificate Authority including identity information, key settings, and password requirements
- **hosts.yaml**: Configuration for host certificates including common names, alternative names, and key settings

## Customization

After running `init`, customize the generated configuration files in the `config` directory to match your requirements.
