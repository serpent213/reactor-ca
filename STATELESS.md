# Database vs. Stateless Approach Analysis

## Stateless Approach
- **Definition**: No dedicated database; certificates and their state exist only as files on disk
- **Advantages**:
  - Simple implementation with minimal dependencies
  - Self-contained (all information derivable from certificate files)
  - Easily backed up through standard file system tools
  - Natural fit for Git-based workflow (specified in requirements)
  - No database schema evolution or migrations needed
- **Disadvantages**:
  - Serial number tracking becomes challenging
  - Certificate metadata (like creation date vs renewal date) harder to track
  - Must parse certificates to extract information for `--list` command
  - Potentially slower for large numbers of certificates

## Database Approach
- **Definition**: Dedicated database (SQLite, JSON, etc.) to track certificate metadata
- **Advantages**:
  - Reliable serial number management
  - Faster queries for certificate information
  - Can store arbitrary metadata not present in certificates
  - Historical tracking of renewals more straightforward
- **Disadvantages**:
  - Additional complexity in code and dependencies
  - Potential for database/filesystem synchronization issues
  - Less transparent to users (hidden state)
  - Extra consideration needed for Git integration

## Hybrid Approach (Recommended)
- **Implementation**: Lightweight metadata file in YAML format alongside certificate files
- **Details**:
  - Store minimal metadata in YAML file (serial numbers, creation dates, renewal history)
  - Use filesystem as primary source of truth
  - Keep metadata file human-readable and Git-friendly
  - Design system to recover if metadata file is lost or corrupted

```yaml
# Example metadata.yaml structure
serial_counter: 1000  # Next serial to use
certificates:
  hostname1.example.com:
    serial: 1001
    created: 2023-01-01
    renewed_at: [2023-06-01]
  hostname2.example.com:
    serial: 1002
    created: 2023-01-02
    renewed_at: []
```

## Rationale for Recommendation
1. **Scale Appropriate**: For a homelab CA, the number of certificates will likely be small
2. **Git Integration**: Lightweight metadata file can be easily committed alongside certificates
3. **Simplicity**: Avoids database complexities while solving the serial number challenge
4. **Robustness**: System can regenerate metadata from certificates if necessary
5. **Future Expandability**: Can evolve to more structured database if requirements grow

## Implementation Strategy
1. Generate unique serial numbers from metadata counter
2. Update metadata when certificates are created/renewed
3. For `--list` command, merge data from metadata file and actual certificate inspection
4. Include recovery function to rebuild metadata from certificate files
5. Keep metadata file format simple and documented for manual editing if needed
