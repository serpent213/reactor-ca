# reactorCA

Write a Python script to manage a CA.

* Use Poetry
* Hosts listed in a YAML file
  * commonName
  * Alternative names (DNS or IP)
  * Each entry includes a relative filename path where the cert should be moved to
* Do we need some kind of internal database to track serial numbers, for example? Or can we do stateless, just relying on the output files?
* Command line options (use `click`)
  * `--init` -- generate a new CA
  * `--generate <hostname>` -- generate a new cert for a host
  * `--renew <hostname>` -- renew cert for a host
  * `--renew-all` -- renew all certs
  * `--list` -- produce a table of CA cert and all host certs including expiration date
  * `--commit` -- Run `git add` for all host certs and internal database (if we use one) and commit with a predefined message
  * `--change-pwd` -- Ask for old and new password (with confirmation) and reencrypt all secrets
* Private keys MUST be encrypted when stored on disk
* Ask for password once if it is required
* Generate CA and shared cert parameters (org, email etc.) in a file for manual editing, provide sensible defaults
* Should be easy to introduce an already existing CA (cert and key) and already existing private keys for hosts
  * Possibility to manually overwrite the relevant files would be enough, but we need to take care of the encryption of private keys. Maybe some `--import-key` command?
