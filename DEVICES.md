# Device Compatibility Database

This document contains information about devices tested with ReactorCA certificates, focusing on algorithm compatibility and performance characteristics.

## About Device Compatibility

Some devices, especially embedded systems, IoT devices, or older network equipment, may not support all cryptographic algorithms available in ReactorCA. This can manifest as:

- Rejected certificates with certain key types
- Slow TLS handshake performance with specific algorithms
- Limited hash algorithm support

Before deploying certificates to production devices, consider testing different key types and hash algorithms to ensure both compatibility and acceptable performance. For detailed information about cryptographic options and their performance implications, see the [Performance Implications section in the README](README.md#performance-implications).

The repo includes [`scripts/measure_https_handshake.sh`](scripts/measure_https_handshake.sh) to measure handshake times.

## Device Database

### AVM FritzBox 7583

**Device Type:** Home Router/Modem

**Firmware Version:** 8.03

**Supported Key Algorithms and Average Handshake Time:**

- RSA-2048: 152 ms
- RSA-3072: 331 ms
- RSA-4096: 765 ms

**Supported Hash Algorithms:**

- SHA256
- SHA384
- SHA512

**Notes:** [fritz-tls](https://github.com/tisba/fritz-tls) works great for automatic deployment.
