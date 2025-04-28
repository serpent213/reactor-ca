# Update - Second Iteration

Read WORKFLOW.md and update the program, tests and README.md accordingly, while taking care of the following additions:

- Drop all Git/commit related functionality.
- Clear (re)labeling: EXPORT means writing a cert or cert bundle to the location specified in the host config. DEPLOY means running a host's deployment script.
- Import Verification: For the `ca ca import` command, include verification steps to ensure the imported certificate and key match before storing them.
- Key export: Add a `ca host export-key HOSTNAME [--out FILE]` action to export private keys unencrypted. Without `--out` print to stdout.
- Certificate Chain Support: Add an optional parameter to the host config to export a "full chain" file (CA + host cert) for services that require them. The files we keep in the store are not influenced by that.
- Add an optional parameter to the host config to allow specification of a deployment script that can be run after export. Add an option `--deploy` to host renew/rekey actions to do that automatically after successful export. Alternatively is will be fired by `ca host deploy`. Export will happen ALWAYS after a cert was generated or updated unless `--no-export` is given.
- Add a global option to read the master password from a file. If that is not given, look for the password in an environment variable. Only ask the user if none of that yielded a password.
- Make sure we have good integration tests for the various workflows and run them.
- Make sure to give a good overview in the README, making clear the intended audience (homelab) and the tradeoffs of this solution, for example no revocation/CRL support (for now), no PKCS#12 support (for now), no automations for rekeying/key deployment (for now). Also include the common workflow examples from the WORKFLOW file in the README, like a "Getting started" section.

Perform the refactoring step by step and ensure linter and tests are happy after each one.
