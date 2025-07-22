analyse this Go code base critically. focus on

- consistent error handling with good UX
- code smells
- deprecated/legacy code
- easy refactorings for simplification

if you want to update/create files, mark output files with `=== $filename ===`, as we do in the input, and bundle them at the end of your response.

current implementation:

--- LLM Response ---
Hello! I've analyzed your Go codebase for `ReactorCA`. This is a well-structured and robust project. The documentation is excellent, and the security considerations are thoughtful. My analysis focuses on refining some patterns to improve consistency, reduce duplication, and enhance user experience even further.

Here is my critical analysis and proposed changes.

### Critical Analysis

#### 1. Consistent Error Handling with Good UX

*   **Strengths**:
    *   The use of a central `internal/domain/errors.go` file is excellent for defining standard application errors.
    *   Specific commands provide helpful hints for common errors (e.g., `ca create` when a CA already exists). This is great UX.
    *   Destructive operations (`ca rekey`, `host clean`) use colored warnings and confirmation prompts, which is a best practice for CLIs.
    *   The top-level error handling in `main.go` correctly exits with a non-zero status code, making it script-friendly.

*   **Areas for Improvement**:
    *   The final error message printed to `stderr` could be more prominent. A simple `Error: ...` prefix, perhaps in red, would make it stand out.
    *   Error handling in commands that process multiple items (`host issue --all`, `host deploy --all`) is good (it continues on error), but the final summary message could better reflect that errors occurred.

#### 2. Code Smells

*   **Duplication**:
    *   The logic to determine the application's root directory (`--root` flag, env var, or `pwd`) is duplicated in `cmd/reactor-ca/commands/root.go` and `init.go`.
    *   The argument validation logic for commands that accept either a `<host-id>` or an `--all` flag is duplicated in `host.go` for the `issue` and `deploy` commands.
    *   The loop structure for processing one or all hosts is also nearly identical in `host issue` and `host deploy`.
    *   Boilerplate code for retrieving the `AppContext` (`cmd.Context().Value(...)`) is present in every command's `RunE` function.

*   **Misplaced Responsibility**:
    *   The `app.ExportHostKeyToFile` method is a thin wrapper around `app.ExportHostKey` and `os.WriteFile`. The responsibility of writing to a file could live entirely within the command layer, simplifying the core `Application` service.
    *   `internal/infra/store/filestore.go`'s `UpdateEncryptedKey` function directly overwrites files. A more robust implementation would use an atomic write-and-rename operation to prevent data loss if the program crashes mid-write.

#### 3. Deprecated/Legacy Code

I found no deprecated or legacy code. The project uses current Go versions, modern libraries (`cobra`, `yaml.v3`), and strong, up-to-date cryptographic primitives (`AES-GCM`, `PBKDF2` with a high iteration count). Your extension of the `pkcs8` library to support AES-GCM is sound, as it correctly uses Go's standard library for the cryptographic implementation.

#### 4. Easy Refactorings for Simplification

The codebase is already quite clean, but the identified code smells point to some great opportunities for simplification through abstraction.

*   **Centralize Helpers**: Create a `helpers.go` file in the `commands` package to house shared logic like:
    *   Retrieving the `*app.Application` instance.
    *   Determining the root path.
    *   A generic function for argument validation (`<id>` vs. `--all`).
    *   A generic function to handle the "process one or all" execution flow.
*   **Simplify the `Application` Service**: Remove `ExportHostKeyToFile` and let the command layer handle writing the exported key to stdout or a file.
*   **Improve File I/O Robustness**: Update `filestore.go` to use atomic file writes.
*   **Enhance Test Readability**: The unit test in `application_test.go` can be slightly refactored to make the test cases and assertions more direct.

### Proposed Refactoring

I've implemented the changes described above. The core logic remains the same, but the command layer is now significantly cleaner and more maintainable.

Here are the new and updated files:

---

=== cmd/reactor-ca/commands/helpers.go ===
package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.dev/reactor-ca/internal/app"
)

// getApp retrieves the application context from the command.
func getApp(cmd *cobra.Command) *app.Application {
	return cmd.Context().Value(appContextKey).(*AppContext).App
}

// getRootPath determines the application's root directory from flags or environment variables.
func getRootPath(cmd *cobra.Command) (string, error) {
	rootPath, err := cmd.Flags().GetString("root")
	if err != nil {
		// This should not happen with a properly configured flag.
		return "", err
	}
	if rootPath == "" {
		rootPath = os.Getenv("REACTOR_CA_ROOT")
	}
	if rootPath == "" {
		rootPath, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("could not determine current directory: %w", err)
		}
	}
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path for root: %w", err)
	}
	return rootPath, nil
}

// hostIDOrAllFlag returns a cobra.PositionalArgs function that validates
// that either a single <host-id> arg is provided, or none if the --all flag is used.
func hostIDOrAllFlag(allFlagName string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		isAll, _ := cmd.Flags().GetBool(allFlagName)
		if !isAll && len(args) != 1 {
			return fmt.Errorf("accepts exactly one argument: <host-id>")
		}
		if isAll && len(args) > 0 {
			return fmt.Errorf("cannot use <host-id> argument when --%s is specified", allFlagName)
		}
		if !isAll && len(args) == 0 {
			return fmt.Errorf("must specify <host-id> or use --%s flag", allFlagName)
		}
		return nil
	}
}

// processHostCmd abstracts the logic for running a command against one or all hosts.
func processHostCmd(cmd *cobra.Command, args []string, allFlagName string,
	singularActionMsg, pluralActionMsg, successMsg string,
	actionFunc func(ctx context.Context, hostID string) error,
) error {
	app := getApp(cmd)
	isAll, _ := cmd.Flags().GetBool(allFlagName)

	var hostIDs []string
	if isAll {
		var err error
		hostIDs, err = app.GetAllHostIDs(cmd.Context())
		if err != nil {
			return err
		}
		if len(hostIDs) == 0 {
			fmt.Println("No hosts found in configuration.")
			return nil
		}
		fmt.Printf(pluralActionMsg+"\n", len(hostIDs))
	} else {
		hostIDs = append(hostIDs, args[0])
	}

	var hasErrors bool
	for _, id := range hostIDs {
		// Only print the singular action message if we are not in "all" mode,
		// as the plural message has already been printed.
		if !isAll {
			fmt.Printf(singularActionMsg+"\n", id)
		}
		err := actionFunc(cmd.Context(), id)
		if err != nil {
			hasErrors = true
			// Don't stop on error if --all is used
			if isAll {
				color.Red("  Error processing host '%s': %v\n", id, err)
				continue
			}
			return err
		}
		if successMsg != "" {
			color.Green(successMsg+"\n", id)
		}
	}

	if isAll {
		if hasErrors {
			color.Yellow("\nDone, but with errors.")
		} else {
			fmt.Println("\nDone.")
		}
	}
	return nil
}

=== cmd/reactor-ca/main.go ===
package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"reactor.dev/reactor-ca/cmd/reactor-ca/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		// Use color for better visibility, and a clear "Error:" prefix.
		fmt.Fprintln(os.Stderr, color.RedString("Error: %v", err))
		os.Exit(1)
	}
}

=== cmd/reactor-ca/commands/ca.go ===
package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.dev/reactor-ca/internal/domain"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the Certificate Authority",
}

// ca create
var caCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new CA key and self-signed certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.CreateCA(cmd.Context())
		if err != nil {
			if err == domain.ErrCAAlreadyExists {
				return fmt.Errorf("%w\n%s", err, "Hint: To replace the existing CA, use 'reactor-ca ca rekey'.")
			}
			return err
		}
		fmt.Println("✅ CA created successfully.")
		return nil
	},
}

// ca renew
var caRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew the CA certificate using the existing key",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.RenewCA(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println("✅ CA renewed successfully.")
		return nil
	},
}

// ca rekey
var caRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Create a new key and a new self-signed certificate, retiring the old ones",
	Long: strings.TrimSpace(`
Create a new key and a new self-signed certificate, retiring the old ones.

WARNING: This is a destructive operation.
The old CA key will be gone forever. All certificates previously issued by the old CA
will no longer be trusted by clients that trust the new CA. You will need to
re-issue and re-deploy all host certificates after this operation.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			yellow := color.New(color.FgYellow).SprintFunc()
			red := color.New(color.FgRed).SprintFunc()

			fmt.Println(yellow("You are about to perform a CA re-key operation."))
			fmt.Println(yellow("This will generate a new private key and certificate for your root CA."))
			fmt.Println(red("This action is irreversible and will invalidate all previously issued certificates."))
			fmt.Println(red("You must re-issue and deploy all host certificates afterwards."))
		}

		err := app.RekeyCA(cmd.Context(), force)
		if err != nil {
			return err
		}
		color.Green("✅ CA re-keyed successfully. Remember to re-issue all host certificates.")
		return nil
	},
}

// ca info
var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display detailed information about the CA certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		info, err := app.InfoCA(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println(info)
		return nil
	},
}

// ca import
var (
	importCertPath string
	importKeyPath  string
)
var caImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an existing CA certificate and private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.ImportCA(cmd.Context(), importCertPath, importKeyPath)
		if err != nil {
			return err
		}
		fmt.Println("✅ CA imported successfully.")
		return nil
	},
}

// ca passwd
var caPasswdCmd = &cobra.Command{
	Use:   "passwd",
	Short: "Change the master password for all encrypted keys in the store",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.ChangePassword(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println("✅ Master password changed successfully for all keys.")
		return nil
	},
}

func init() {
	caImportCmd.Flags().StringVar(&importCertPath, "cert", "", "Path to the CA certificate file (PEM format)")
	caImportCmd.Flags().StringVar(&importKeyPath, "key", "", "Path to the CA private key file (PEM format)")
	_ = caImportCmd.MarkFlagRequired("cert")
	_ = caImportCmd.MarkFlagRequired("key")

	caRekeyCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	caCmd.AddCommand(caCreateCmd)
	caCmd.AddCommand(caRenewCmd)
	caCmd.AddCommand(caRekeyCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caImportCmd)
	caCmd.AddCommand(caPasswdCmd)
}

=== cmd/reactor-ca/commands/config.go ===
package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration files",
}

// config validate
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the syntax and schema of ca.yaml and hosts.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.ValidateConfig(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Println("✅ Configuration files are valid.")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}

=== cmd/reactor-ca/commands/host.go ===
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.dev/reactor-ca/internal/domain"
)

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Manage host certificates",
}

// host issue
var (
	rekeyHost     bool
	deployHost    bool
	issueAllHosts bool
)
var hostIssueCmd = &cobra.Command{
	Use:   "issue <host-id>",
	Short: "Issue or renew a certificate for one or all hosts",
	Long: `Issues or renews a certificate for a host defined in hosts.yaml.
Use '--all' to issue for all defined hosts.
A new key is generated only if one does not already exist, unless --rekey is specified.`,
	Args: hostIDOrAllFlag("all"),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := func(ctx context.Context, hostID string) error {
			app := getApp(cmd)
			return app.IssueHost(ctx, hostID, rekeyHost, deployHost)
		}

		return processHostCmd(cmd, args, "all",
			"Issuing certificate for host '%s'...",
			"Issuing certificates for all %d hosts...",
			"  ✅ Successfully issued certificate for '%s'",
			action,
		)
	},
}

// host list
var (
	listExpired    bool
	listExpiringIn int
	listJSON       bool
)
var hostListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all host certificates in the store with their status",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		list, err := app.ListHosts(cmd.Context())
		if err != nil {
			return err
		}

		filteredList := filterHostList(list, listExpired, listExpiringIn)

		if listJSON {
			b, err := json.MarshalIndent(filteredList, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal host list to JSON: %w", err)
			}
			fmt.Println(string(b))
			return nil
		}

		printHostTable(filteredList)
		return nil
	},
}

func filterHostList(list []*domain.HostInfo, expired bool, expiringIn int) []*domain.HostInfo {
	if !expired && expiringIn == 0 {
		return list
	}

	var filtered []*domain.HostInfo
	for _, h := range list {
		if expired && h.DaysRemaining < 0 {
			filtered = append(filtered, h)
			continue
		}
		if expiringIn > 0 && h.DaysRemaining >= 0 && h.DaysRemaining < int64(expiringIn) {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

func printHostTable(list []*domain.HostInfo) {
	if len(list) == 0 {
		fmt.Println("No host certificates found in the store.")
		return
	}

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	// Header
	fmt.Printf("%-30s | %-25s | %s\n", "HOST ID", "EXPIRES (UTC)", "STATUS / DAYS REMAINING")
	fmt.Println(strings.Repeat("-", 78))

	for _, h := range list {
		var status string
		daysStr := fmt.Sprintf("%d", h.DaysRemaining)
		if h.DaysRemaining < 0 {
			status = red("EXPIRED")
		} else if h.DaysRemaining < 30 {
			status = red(daysStr)
		} else if h.DaysRemaining < 90 {
			status = yellow(daysStr)
		} else {
			status = green(daysStr)
		}

		fmt.Printf("%-30s | %-25s | %s\n",
			h.ID,
			h.NotAfter.UTC().Format(time.RFC3339),
			status)
	}
}

// host info
var hostInfoCmd = &cobra.Command{
	Use:   "info <host-id>",
	Short: "Display detailed information about a specific host certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		info, err := app.InfoHost(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		fmt.Println(info)
		return nil
	},
}

// host deploy
var deployAllHosts bool
var hostDeployCmd = &cobra.Command{
	Use:   "deploy <host-id>",
	Short: "Run the configured deployment command for one or all hosts",
	Args:  hostIDOrAllFlag("all"),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := func(ctx context.Context, hostID string) error {
			app := getApp(cmd)
			return app.DeployHost(ctx, hostID)
		}

		return processHostCmd(cmd, args, "all",
			"Deploying certificate for host '%s'...",
			"Deploying certificates for all %d hosts...",
			"  ✅ Successfully deployed certificate for '%s'",
			action,
		)
	},
}

// host export-key
var exportKeyOutPath string
var hostExportKeyCmd = &cobra.Command{
	Use:   "export-key <host-id>",
	Short: "Export the unencrypted private key for a host",
	Long:  `Exports the unencrypted private key for a host to a specified file or stdout.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		hostID := args[0]
		pemKey, err := app.ExportHostKey(cmd.Context(), hostID)
		if err != nil {
			return err
		}

		if exportKeyOutPath == "" || exportKeyOutPath == "-" {
			fmt.Print(string(pemKey))
		} else {
			// Write with secure permissions (0600)
			if err := os.WriteFile(exportKeyOutPath, pemKey, 0600); err != nil {
				return fmt.Errorf("failed to write key to %s: %w", exportKeyOutPath, err)
			}
			fmt.Printf("✅ Unencrypted key for '%s' exported to %s\n", hostID, exportKeyOutPath)
		}
		return nil
	},
}

// host import-key
var importHostKeyPath string
var hostImportKeyCmd = &cobra.Command{
	Use:   "import-key <host-id>",
	Short: "Import a pre-existing private key for a host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		err := app.ImportHostKey(cmd.Context(), args[0], importHostKeyPath)
		if err != nil {
			return err
		}
		fmt.Printf("✅ Key for host '%s' imported successfully. Run 'host issue %s' to create a matching certificate.\n", args[0], args[0])
		return nil
	},
}

// host sign-csr
var (
	csrPath string
	csrOut  string
	csrDays int
)
var hostSignCSRCmd = &cobra.Command{
	Use:   "sign-csr",
	Short: "Sign an external Certificate Signing Request (CSR)",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		certPEM, err := app.SignCSR(cmd.Context(), csrPath, csrDays)
		if err != nil {
			return err
		}

		if csrOut == "" || csrOut == "-" {
			fmt.Print(string(certPEM))
		} else {
			if err := os.WriteFile(csrOut, certPEM, 0644); err != nil {
				return fmt.Errorf("failed to write certificate to %s: %w", csrOut, err)
			}
			fmt.Printf("✅ Certificate signed successfully and saved to %s\n", csrOut)
		}
		return nil
	},
}

// host clean
var forceClean bool
var hostCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Prune certificates/keys from the store for hosts no longer in hosts.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		pruned, err := app.CleanHosts(cmd.Context(), forceClean)
		if err != nil {
			return err
		}

		if len(pruned) == 0 {
			fmt.Println("Store is already clean. No hosts to prune.")
			return nil
		}

		fmt.Println("Pruned the following hosts from the store:")
		for _, id := range pruned {
			fmt.Printf("- %s\n", id)
		}
		return nil
	},
}

func init() {
	// host issue
	hostIssueCmd.Flags().BoolVar(&rekeyHost, "rekey", false, "Force generation of a new private key")
	hostIssueCmd.Flags().BoolVar(&deployHost, "deploy", false, "Execute the deployment step after successful issuance")
	hostIssueCmd.Flags().BoolVar(&issueAllHosts, "all", false, "Issue certificates for all hosts defined in hosts.yaml")
	hostCmd.AddCommand(hostIssueCmd)

	// host list
	hostListCmd.Flags().BoolVar(&listExpired, "expired", false, "Only show expired certificates")
	hostListCmd.Flags().IntVar(&listExpiringIn, "expiring-in", 0, "Only show certificates expiring in the next N days")
	hostListCmd.Flags().BoolVar(&listJSON, "json", false, "Output the list in JSON format")
	hostCmd.AddCommand(hostListCmd)

	// host info
	hostCmd.AddCommand(hostInfoCmd)

	// host deploy
	hostDeployCmd.Flags().BoolVar(&deployAllHosts, "all", false, "Deploy certificates for all hosts with a deploy command")
	hostCmd.AddCommand(hostDeployCmd)

	// host export-key
	hostExportKeyCmd.Flags().StringVarP(&exportKeyOutPath, "out", "o", "", "Output file path for the key (default: stdout)")
	hostCmd.AddCommand(hostExportKeyCmd)

	// host import-key
	hostImportKeyCmd.Flags().StringVar(&importHostKeyPath, "key", "", "Path to the private key file to import (PEM format)")
	_ = hostImportKeyCmd.MarkFlagRequired("key")
	hostCmd.AddCommand(hostImportKeyCmd)

	// host sign-csr
	hostSignCSRCmd.Flags().StringVar(&csrPath, "csr", "", "Path to the Certificate Signing Request file (PEM format)")
	hostSignCSRCmd.Flags().StringVarP(&csrOut, "out", "o", "", "Output file path for the signed certificate (default: stdout)")
	hostSignCSRCmd.Flags().IntVar(&csrDays, "days", 365, "Number of days the certificate should be valid for")
	_ = hostSignCSRCmd.MarkFlagRequired("csr")
	hostCmd.AddCommand(hostSignCSRCmd)

	// host clean
	hostCleanCmd.Flags().BoolVar(&forceClean, "force", false, "Do not ask for confirmation before deleting")
	hostCmd.AddCommand(hostCleanCmd)
}

=== cmd/reactor-ca/commands/init.go ===
package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var forceInit bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize config and store directories",
	Long:  `Creates the necessary directory structure (config/, store/) and populates it with default configuration files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootPath, err := getRootPath(cmd)
		if err != nil {
			return err
		}

		fmt.Printf("Initializing Reactor CA in %s...\n", rootPath)

		dirs := []string{
			filepath.Join(rootPath, "config"),
			filepath.Join(rootPath, "store"),
			filepath.Join(rootPath, "store", "ca"),
			filepath.Join(rootPath, "store", "hosts"),
		}

		for _, dir := range dirs {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
			fmt.Printf("✓ Created directory: %s\n", dir)
		}

		files := map[string]string{
			filepath.Join(rootPath, "config", "ca.yaml"):    defaultCaYAML,
			filepath.Join(rootPath, "config", "hosts.yaml"): defaultHostsYAML,
		}

		for path, content := range files {
			if _, err := os.Stat(path); err == nil && !forceInit {
				fmt.Printf("! Skipping existing file: %s (use --force to overwrite)\n", path)
				continue
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write file %s: %w", path, err)
			}
			fmt.Printf("✓ Created config file: %s\n", path)
		}

		fmt.Println("\nInitialization complete. Review the files in config/ and then run 'reactor-ca ca create'.")
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Overwrite existing configuration files")
}

const defaultCaYAML = `# ReactorCA: Certificate Authority Configuration
# This file defines the properties of your root Certificate Authority.

ca:
  # --- Subject Details ---
  # These values are used to build the distinguished name (DN) of the CA certificate.
  subject:
    common_name: "Reactor Homelab CA"
    organization: "Reactor Industries"
    organization_unit: "IT Department"
    country: "DE"                 # 2-letter country code
    state: "Berlin"               # State or province
    locality: "Berlin"            # City or locality
    email: "admin@reactor.dev"  # Administrative contact

  # --- Validity Period ---
  # How long the CA certificate will be valid for.
  # Specify exactly one of 'years' or 'days'.
  validity:
    years: 10
    # days: 3650

  # --- Cryptographic Settings ---
  # The algorithm used for the CA's private key.
  # Supported: RSA2048, RSA3072, RSA4096, ECP256, ECP384, ECP521, ED25519
  key_algorithm: "ECP384"

  # The hash algorithm used for the certificate signature.
  # Supported: SHA256, SHA384, SHA512
  hash_algorithm: "SHA384"

  # --- Password Management ---
  # Defines how the master password for encrypting private keys is handled.
  password:
    # Minimum required password length during interactive prompts.
    min_length: 12

    # Optional: Path to a file containing the master password.
    # If set, the CLI will not prompt for a password.
    # file: "/run/secrets/reactor_ca_password"

    # Optional: Name of the environment variable containing the master password.
    # This is checked if 'file' is not set or does not exist.
    env_var: "REACTOR_CA_PASSWORD"
`

const defaultHostsYAML = `# ReactorCA: Host Certificate Configuration
# This file defines the certificates you want to issue for your hosts/services.

hosts:
  # This is a unique ID for the certificate, used in CLI commands (e.g., 'reactor-ca host issue web-server').
  web-server-example:
    # --- Subject Details ---
    # The Common Name (CN) is typically the primary fully-qualified domain name (FQDN).
    subject:
      common_name: "web.reactor.local"
      # Other subject fields are optional and will inherit from ca.yaml if not specified.
      # organization_unit: "Web Services"

    # --- Subject Alternative Names (SANs) ---
    # A list of additional names the certificate should be valid for. This is highly recommended.
    alternative_names:
      dns:
        - "web.reactor.local"
        - "grafana.reactor.local"
      ip:
        - "192.168.1.100"
        - "10.10.0.1"

    # --- Validity Period ---
    # How long the host certificate will be valid for.
    validity:
      years: 1
      # days: 365

    # --- Cryptographic Settings ---
    # Algorithm for this specific host's key. Defaults to CA's key_algorithm if unset.
    key_algorithm: "RSA2048"
    # Signing hash for this specific certificate. Defaults to CA's hash_algorithm if unset.
    hash_algorithm: "SHA256"

    # --- Export & Deploy ---
    # Optional: Defines where to copy the certificate files after they are issued.
    # The parent directory will be created if it doesn't exist.
    export:
      # Path to save the host certificate (PEM format).
      cert: "/tmp/reactor-ca/exports/web-server/cert.pem"
      # Path to save the full chain (host certificate + CA certificate).
      chain: "/tmp/reactor-ca/exports/web-server/chain.pem"

    # Optional: A list of commands to run after the certificate has been issued and exported.
    # These are executed as a shell script using 'bash -c'.
    # Variables:
    # - ${cert}: Absolute path to the exported certificate file.
    # - ${chain}: Absolute path to the exported chain file.
    # - ${private_key}: Absolute path to a temporary, unencrypted private key file.
    #   This file is created with secure permissions and is automatically deleted after the script runs.
    deploy:
      commands:
        # - "scp ${chain} ${cert} user@host:/etc/ssl/certs/"
        # - "ssh user@host -- 'systemctl reload nginx'"
        - "echo 'Deployment for web-server-example would run now.'"
        - "echo 'Cert Path: ${cert}'"
        - "echo 'Key Path: ${private_key}'"
`

=== cmd/reactor-ca/commands/root.go ===
package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"reactor.dev/reactor-ca/internal/app"
	"reactor.dev/reactor-ca/internal/infra/config"
	"reactor.dev/reactor-ca/internal/infra/crypto"
	"reactor.dev/reactor-ca/internal/infra/exec"
	"reactor.dev/reactor-ca/internal/infra/logging"
	"reactor.dev/reactor-ca/internal/infra/password"
	"reactor.dev/reactor-ca/internal/infra/store"
)

// AppContext holds all the dependencies for the application.
// It is attached to the command's context for access in RunE functions.
type AppContext struct {
	App *app.Application
}

var appContextKey = &struct{}{}

var rootCmd = &cobra.Command{
	Use:   "reactor-ca",
	Short: "ReactorCA is a tool for managing a private PKI.",
	Long: `ReactorCA provides a secure, reliable, and user-friendly Command-Line
Interface (CLI) for managing a private Public Key Infrastructure (PKI)
suitable for homelab and small-to-medium business environments.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Do not run dependency injection for the 'init' command or help.
		if cmd.Name() == "init" || cmd.Name() == "help" || cmd.Name() == "completion" {
			return nil
		}

		rootPath, err := getRootPath(cmd)
		if err != nil {
			return err
		}

		// Basic validation to ensure we are in a reactor-ca directory
		configPath := filepath.Join(rootPath, "config")
		storePath := filepath.Join(rootPath, "store")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return fmt.Errorf("config directory not found at %s. Did you run 'reactor-ca init'?", configPath)
		}
		if _, err := os.Stat(storePath); os.IsNotExist(err) {
			return fmt.Errorf("store directory not found at %s. Did you run 'reactor-ca init'?", storePath)
		}

		// Dependency Injection
		logger, err := logging.NewFileLogger(filepath.Join(storePath, "ca.log"))
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		fileStore := store.NewFileStore(storePath)
		configLoader := config.NewYAMLConfigLoader(configPath)
		cryptoSvc := crypto.NewService()
		passwordProvider := password.NewProvider()
		commander := exec.NewCommander()

		application := app.NewApplication(
			rootPath,
			logger,
			configLoader,
			fileStore,
			cryptoSvc,
			passwordProvider,
			commander,
		)

		ctx := context.WithValue(cmd.Context(), appContextKey, &AppContext{App: application})
		cmd.SetContext(ctx)

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().String("root", "", "Root directory for config and store (env: REACTOR_CA_ROOT)")

	// Add subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(hostCmd)
	rootCmd.AddCommand(configCmd)
}

=== internal/app/application.go ===
package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reactor.dev/reactor-ca/internal/domain"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath         string
	logger           domain.Logger
	configLoader     domain.ConfigLoader
	store            domain.Store
	cryptoSvc        domain.CryptoService
	passwordProvider domain.PasswordProvider
	commander        domain.Commander
}

// NewApplication creates a new Application instance.
func NewApplication(
	rootPath string,
	logger domain.Logger,
	configLoader domain.ConfigLoader,
	store domain.Store,
	cryptoSvc domain.CryptoService,
	passwordProvider domain.PasswordProvider,
	commander domain.Commander,
) *Application {
	return &Application{
		rootPath:         rootPath,
		logger:           logger,
		configLoader:     configLoader,
		store:            store,
		cryptoSvc:        cryptoSvc,
		passwordProvider: passwordProvider,
		commander:        commander,
	}
}

// ValidateConfig checks if the configuration files are valid.
func (a *Application) ValidateConfig(ctx context.Context) error {
	a.logger.Log("Validating configuration files...")
	if _, err := a.configLoader.LoadCA(); err != nil {
		return fmt.Errorf("invalid ca.yaml: %w", err)
	}
	if _, err := a.configLoader.LoadHosts(); err != nil {
		return fmt.Errorf("invalid hosts.yaml: %w", err)
	}

	a.logger.Log("Configuration files are valid.")
	return nil
}

// CreateCA creates a new Certificate Authority.
func (a *Application) CreateCA(ctx context.Context) error {
	return a.createCA(ctx, false)
}

// createCA creates a new Certificate Authority with optional force parameter.
func (a *Application) createCA(ctx context.Context, force bool) error {
	if !force {
		exists, err := a.store.CAExists()
		if err != nil {
			return fmt.Errorf("could not check for existing CA: %w", err)
		}
		if exists {
			return domain.ErrCAAlreadyExists
		}
	}

	a.logger.Log("Loading CA configuration...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	a.logger.Log(fmt.Sprintf("Generating private key with algorithm %s...", cfg.CA.KeyAlgorithm))
	key, err := a.cryptoSvc.GeneratePrivateKey(cfg.CA.KeyAlgorithm)
	if err != nil {
		return err
	}

	a.logger.Log("Creating self-signed root certificate...")
	cert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}

	a.logger.Log("Encrypting private key...")
	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	a.logger.Log("Saving CA certificate and encrypted key to store...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(cert)
	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}

	a.logger.Log("CA created successfully.")
	return nil
}

// RenewCA renews the CA certificate using the existing key.
func (a *Application) RenewCA(ctx context.Context) error {
	a.logger.Log("Renewing CA certificate...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	a.logger.Log("Loading existing CA key...")
	encryptedKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}

	a.logger.Log("Getting master password...")
	password, err := a.passwordProvider.GetMasterPassword(ctx, cfg.CA.Password)
	if err != nil {
		return err
	}

	key, err := a.cryptoSvc.DecryptPrivateKey(encryptedKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err // Return the specific error for better UX
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	a.logger.Log("Creating new self-signed root certificate...")
	newCert, err := a.cryptoSvc.CreateRootCertificate(cfg, key)
	if err != nil {
		return err
	}

	a.logger.Log("Saving renewed CA certificate...")
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(newCert)
	// We only need to save the cert, as the key is unchanged.
	if err := a.store.SaveCA(certPEM, nil); err != nil {
		return err
	}

	a.logger.Log("CA renewed successfully.")
	return nil
}

// RekeyCA creates a new key and certificate, replacing the old ones.
func (a *Application) RekeyCA(ctx context.Context, force bool) error {
	a.logger.Log("Re-keying CA. This will replace the existing CA key and certificate.")
	if !force {
		confirmed, err := a.passwordProvider.Confirm("Are you sure you want to proceed? [y/N]: ")
		if err != nil {
			return err
		}
		if !confirmed {
			return domain.ErrActionAborted
		}
	}
	// Create new CA, allowing overwrite of existing CA
	return a.createCA(ctx, true)
}

// InfoCA returns a formatted string with details about the CA certificate.
func (a *Application) InfoCA(ctx context.Context) (string, error) {
	a.logger.Log("Loading CA certificate info...")
	cert, err := a.store.LoadCACert()
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ImportCA imports an existing CA from external files.
func (a *Application) ImportCA(ctx context.Context, certPath, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing CA from cert: %s, key: %s", certPath, keyPath))

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := a.cryptoSvc.ParseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	if err := a.cryptoSvc.ValidateKeyPair(cert, key); err != nil {
		return err
	}

	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetPasswordForImport(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	if err := a.store.SaveCA(certPEM, encryptedKey); err != nil {
		return err
	}
	a.logger.Log("CA imported successfully.")
	return nil
}

// ChangePassword re-encrypts all keys in the store with a new password.
func (a *Application) ChangePassword(ctx context.Context) error {
	a.logger.Log("Starting password change process...")
	cfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	// Create a backup before proceeding
	backupPath, err := a.backupStore("passwd-change")
	if err != nil {
		return fmt.Errorf("failed to create store backup before password change: %w", err)
	}
	a.logger.Log(fmt.Sprintf("Created a backup of the store at: %s", backupPath))
	fmt.Printf("A backup of your store has been created at %s\n", backupPath)

	fmt.Println("Enter current master password:")
	oldPassword, err := a.passwordProvider.GetMasterPassword(ctx, cfg.CA.Password)
	if err != nil {
		return err
	}

	fmt.Println("Enter new master password:")
	newPassword, err := a.passwordProvider.GetNewMasterPassword(ctx, cfg.CA.Password.MinLength)
	if err != nil {
		return err
	}

	keyPaths, err := a.store.GetAllEncryptedKeyPaths()
	if err != nil {
		return fmt.Errorf("failed to list keys in store: %w", err)
	}

	type reEncryptedKey struct {
		path string
		key  []byte
	}
	reEncryptedKeys := make([]reEncryptedKey, 0, len(keyPaths))

	a.logger.Log(fmt.Sprintf("Decrypting %d keys with old password...", len(keyPaths)))
	for _, path := range keyPaths {
		encryptedPEM, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key %s: %w", path, err)
		}
		key, err := a.cryptoSvc.DecryptPrivateKey(encryptedPEM, oldPassword)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return fmt.Errorf("%w for key %s. Aborting. No changes have been made", err, filepath.Base(path))
			}
			return fmt.Errorf("failed to decrypt key %s: %w. Aborting password change", filepath.Base(path), err)
		}

		reEncrypted, err := a.cryptoSvc.EncryptPrivateKey(key, newPassword)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt key %s: %w", path, err)
		}

		reEncryptedKeys = append(reEncryptedKeys, reEncryptedKey{path: path, key: reEncrypted})
	}

	a.logger.Log("All keys decrypted successfully. Writing re-encrypted keys back to store...")
	for _, item := range reEncryptedKeys {
		if err := a.store.UpdateEncryptedKey(item.path, item.key); err != nil {
			return fmt.Errorf("FATAL: failed to write re-encrypted key %s. Your keys may be in an inconsistent state. PLEASE RESTORE FROM THE BACKUP. Error: %w", item.path, err)
		}
	}

	a.logger.Log("Password change complete. Backup can be removed if everything is working.")
	return nil
}

// GetAllHostIDs returns a list of all host IDs from the configuration.
func (a *Application) GetAllHostIDs(ctx context.Context) ([]string, error) {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hostsCfg.Hosts))
	for id := range hostsCfg.Hosts {
		ids = append(ids, id)
	}
	return ids, nil
}

// IssueHost creates or renews a certificate for a single host.
func (a *Application) IssueHost(ctx context.Context, hostID string, rekey, shouldDeploy bool) error {
	a.logger.Log(fmt.Sprintf("Starting certificate issuance for host '%s'", hostID))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return err
	}

	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}

	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		if errors.Is(err, domain.ErrIncorrectPassword) {
			return err
		}
		return fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	var hostKey crypto.Signer
	keyExists, err := a.store.HostKeyExists(hostID)
	if err != nil {
		return err
	}
	if rekey || !keyExists {
		if rekey {
			a.logger.Log(fmt.Sprintf("Rekey requested for '%s'. Generating new key.", hostID))
		} else {
			a.logger.Log(fmt.Sprintf("No key found for '%s'. Generating new key.", hostID))
		}
		algo := hostCfg.KeyAlgorithm
		if algo == "" {
			algo = caCfg.CA.KeyAlgorithm
		}
		hostKey, err = a.cryptoSvc.GeneratePrivateKey(algo)
		if err != nil {
			return err
		}
		encryptedHostKey, err := a.cryptoSvc.EncryptPrivateKey(hostKey, password)
		if err != nil {
			return err
		}
		if err := a.store.SaveHostKey(hostID, encryptedHostKey); err != nil {
			return err
		}
	} else {
		a.logger.Log(fmt.Sprintf("Using existing key for '%s'.", hostID))
		hostKeyData, err := a.store.LoadHostKey(hostID)
		if err != nil {
			return err
		}
		hostKey, err = a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
		if err != nil {
			if errors.Is(err, domain.ErrIncorrectPassword) {
				return err
			}
			return fmt.Errorf("failed to decrypt host key: %w", err)
		}
	}

	a.logger.Log(fmt.Sprintf("Creating certificate for '%s'...", hostID))
	hostCert, err := a.cryptoSvc.CreateHostCertificate(&hostCfg, caCert, caKey, hostKey.Public())
	if err != nil {
		return err
	}
	certPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
	if err := a.store.SaveHostCert(hostID, certPEM); err != nil {
		return err
	}

	if err := a.exportHostFiles(hostID, hostCert, caCert); err != nil {
		return err
	}

	if shouldDeploy {
		a.logger.Log(fmt.Sprintf("Deployment requested for '%s'.", hostID))
		if err := a.DeployHost(ctx, hostID); err != nil {
			return fmt.Errorf("deployment failed: %w", err)
		}
	}
	a.logger.Log(fmt.Sprintf("Successfully issued certificate for '%s'", hostID))
	return nil
}

func (a *Application) exportHostFiles(hostID string, hostCert, caCert *x509.Certificate) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg := hostsCfg.Hosts[hostID]

	// Export certificate
	if hostCfg.Export.Cert != "" {
		certPath := a.resolvePath(hostCfg.Export.Cert)
		a.logger.Log(fmt.Sprintf("Exporting certificate to %s", certPath))
		if err := a.writeFileWithDir(certPath, a.cryptoSvc.EncodeCertificateToPEM(hostCert), 0644); err != nil {
			return fmt.Errorf("failed to export certificate: %w", err)
		}
	}

	// Export chain
	if hostCfg.Export.Chain != "" {
		chainPath := a.resolvePath(hostCfg.Export.Chain)
		a.logger.Log(fmt.Sprintf("Exporting certificate chain to %s", chainPath))
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		caCertPEM := a.cryptoSvc.EncodeCertificateToPEM(caCert)
		chain := bytes.Join([][]byte{hostCertPEM, caCertPEM}, []byte{})
		if err := a.writeFileWithDir(chainPath, chain, 0644); err != nil {
			return fmt.Errorf("failed to export chain: %w", err)
		}
	}
	return nil
}

// DeployHost runs the deployment command for a host.
func (a *Application) DeployHost(ctx context.Context, hostID string) error {
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	hostCfg, ok := hostsCfg.Hosts[hostID]
	if !ok {
		return domain.ErrHostNotFoundInConfig
	}

	if len(hostCfg.Deploy.Commands) == 0 {
		return domain.ErrNoDeployCommand
	}
	a.logger.Log(fmt.Sprintf("Running %d deploy command(s) for '%s'", len(hostCfg.Deploy.Commands), hostID))

	// Get unencrypted key
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return err
	}
	keyPEM, err := a.cryptoSvc.EncodeKeyToPEM(hostKey)
	if err != nil {
		return err
	}

	// Create temp file for key
	tempKeyFile, err := os.CreateTemp("", "reactor-ca-key-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temp key file: %w", err)
	}
	defer os.Remove(tempKeyFile.Name())
	if err := os.Chmod(tempKeyFile.Name(), 0600); err != nil {
		return fmt.Errorf("failed to set permissions on temp key file: %w", err)
	}
	if _, err := tempKeyFile.Write(keyPEM); err != nil {
		return fmt.Errorf("failed to write to temp key file: %w", err)
	}
	if err := tempKeyFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp key file: %w", err)
	}

	// Variable substitution
	certPath := a.resolvePath(hostCfg.Export.Cert)
	chainPath := a.resolvePath(hostCfg.Export.Chain)

	// If export paths are not defined, we must create temporary files for them too.
	if certPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		hostCertPEM := a.cryptoSvc.EncodeCertificateToPEM(hostCert)
		tempCertFile, err := os.CreateTemp("", "reactor-ca-cert-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp cert file: %w", err)
		}
		defer os.Remove(tempCertFile.Name())
		if _, err := tempCertFile.Write(hostCertPEM); err != nil {
			return fmt.Errorf("failed to write to temp cert file: %w", err)
		}
		if err := tempCertFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp cert file: %w", err)
		}
		certPath = tempCertFile.Name()
	}
	if chainPath == a.rootPath { // Heuristic: empty export path resolves to root
		hostCert, err := a.store.LoadHostCert(hostID)
		if err != nil {
			return err
		}
		caCert, err := a.store.LoadCACert()
		if err != nil {
			return err
		}
		chainPEM := bytes.Join([][]byte{
			a.cryptoSvc.EncodeCertificateToPEM(hostCert),
			a.cryptoSvc.EncodeCertificateToPEM(caCert),
		}, []byte{})

		tempChainFile, err := os.CreateTemp("", "reactor-ca-chain-*.pem")
		if err != nil {
			return fmt.Errorf("failed to create temp chain file: %w", err)
		}
		defer os.Remove(tempChainFile.Name())
		if _, err := tempChainFile.Write(chainPEM); err != nil {
			return fmt.Errorf("failed to write to temp chain file: %w", err)
		}
		if err := tempChainFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp chain file: %w", err)
		}
		chainPath = tempChainFile.Name()
	}

	replacer := strings.NewReplacer(
		"${cert}", certPath,
		"${chain}", chainPath,
		"${private_key}", tempKeyFile.Name(),
	)

	var substitutedCommands []string
	for _, cmd := range hostCfg.Deploy.Commands {
		substitutedCommands = append(substitutedCommands, replacer.Replace(cmd))
	}

	// Create shell script with safety flags
	shellScript := "set -euo pipefail\n" + strings.Join(substitutedCommands, "\n")

	// Execute via shell
	a.logger.Log(fmt.Sprintf("Executing deploy script for '%s':\n%s", hostID, shellScript))
	output, err := a.commander.Execute("bash", "-c", shellScript)
	if err != nil {
		return fmt.Errorf("deploy command failed: %w\nOutput:\n%s", err, string(output))
	}
	a.logger.Log(fmt.Sprintf("Deploy commands for '%s' successful. Output: %s", hostID, string(output)))
	return nil
}

// ListHosts returns information about all host certificates in the store.
func (a *Application) ListHosts(ctx context.Context) ([]*domain.HostInfo, error) {
	a.logger.Log("Listing hosts from store...")
	hostIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}
	infoList := make([]*domain.HostInfo, 0, len(hostIDs))
	for _, id := range hostIDs {
		cert, err := a.store.LoadHostCert(id)
		if err != nil {
			a.logger.Error(fmt.Sprintf("Could not load certificate for host '%s', skipping: %v", id, err))
			continue
		}
		daysRemaining := int64(time.Until(cert.NotAfter).Hours() / 24)
		infoList = append(infoList, &domain.HostInfo{
			ID:            id,
			CommonName:    cert.Subject.CommonName,
			NotAfter:      cert.NotAfter,
			DaysRemaining: daysRemaining,
		})
	}
	return infoList, nil
}

// InfoHost returns details for a specific host certificate.
func (a *Application) InfoHost(ctx context.Context, hostID string) (string, error) {
	a.logger.Log(fmt.Sprintf("Loading host certificate info for '%s'...", hostID))
	cert, err := a.store.LoadHostCert(hostID)
	if err != nil {
		return "", err
	}
	return a.cryptoSvc.FormatCertificateInfo(cert), nil
}

// ExportHostKey returns the unencrypted private key for a host.
func (a *Application) ExportHostKey(ctx context.Context, hostID string) ([]byte, error) {
	a.logger.Log(fmt.Sprintf("Exporting private key for host '%s'", hostID))
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return nil, err
	}
	hostKeyData, err := a.store.LoadHostKey(hostID)
	if err != nil {
		return nil, err
	}
	hostKey, err := a.cryptoSvc.DecryptPrivateKey(hostKeyData, password)
	if err != nil {
		return nil, err
	}
	return a.cryptoSvc.EncodeKeyToPEM(hostKey)
}

// ImportHostKey imports an external key for a host.
func (a *Application) ImportHostKey(ctx context.Context, hostID, keyPath string) error {
	a.logger.Log(fmt.Sprintf("Importing key for host '%s' from %s", hostID, keyPath))
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return err
	}
	if _, ok := hostsCfg.Hosts[hostID]; !ok {
		return domain.ErrHostNotFoundInConfig
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := a.cryptoSvc.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return err
	}

	encryptedKey, err := a.cryptoSvc.EncryptPrivateKey(key, password)
	if err != nil {
		return err
	}

	if err := a.store.SaveHostKey(hostID, encryptedKey); err != nil {
		return err
	}
	a.logger.Log(fmt.Sprintf("Key for host '%s' imported successfully.", hostID))
	return nil
}

// SignCSR signs an external Certificate Signing Request.
func (a *Application) SignCSR(ctx context.Context, csrPath string, validityDays int) ([]byte, error) {
	a.logger.Log(fmt.Sprintf("Signing CSR from %s", csrPath))
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSR file: %w", err)
	}
	csr, err := a.cryptoSvc.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}

	caCert, err := a.store.LoadCACert()
	if err != nil {
		return nil, err
	}
	caCfg, err := a.configLoader.LoadCA()
	if err != nil {
		return nil, err
	}
	password, err := a.passwordProvider.GetMasterPassword(ctx, caCfg.CA.Password)
	if err != nil {
		return nil, err
	}
	caKeyData, err := a.store.LoadCAKey()
	if err != nil {
		return nil, err
	}
	caKey, err := a.cryptoSvc.DecryptPrivateKey(caKeyData, password)
	if err != nil {
		return nil, err
	}

	cert, err := a.cryptoSvc.SignCSR(csr, caCert, caKey, validityDays)
	if err != nil {
		return nil, err
	}

	a.logger.Log("CSR signed successfully.")
	return a.cryptoSvc.EncodeCertificateToPEM(cert), nil
}

// CleanHosts removes hosts from the store that are no longer in the config.
func (a *Application) CleanHosts(ctx context.Context, force bool) ([]string, error) {
	a.logger.Log("Checking for hosts to clean from the store...")
	hostsCfg, err := a.configLoader.LoadHosts()
	if err != nil {
		return nil, err
	}
	storeIDs, err := a.store.ListHostIDs()
	if err != nil {
		return nil, err
	}

	configIDs := make(map[string]struct{})
	for id := range hostsCfg.Hosts {
		configIDs[id] = struct{}{}
	}

	var toPrune []string
	for _, id := range storeIDs {
		if _, ok := configIDs[id]; !ok {
			toPrune = append(toPrune, id)
		}
	}

	if len(toPrune) == 0 {
		return nil, nil
	}

	fmt.Println("The following hosts exist in the store but not in hosts.yaml:")
	for _, id := range toPrune {
		fmt.Printf("- %s\n", id)
	}

	if !force {
		confirmed, err := a.passwordProvider.Confirm("Do you want to permanently delete these hosts from the store? [y/N]: ")
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return nil, domain.ErrActionAborted
		}
	}

	for _, id := range toPrune {
		a.logger.Log(fmt.Sprintf("Deleting host '%s' from store...", id))
		if err := a.store.DeleteHost(id); err != nil {
			a.logger.Error(fmt.Sprintf("Failed to delete host '%s': %v", id, err))
			// Continue to next host
		}
	}
	a.logger.Log("Host cleaning complete.")
	return toPrune, nil
}

func (a *Application) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(a.rootPath, path)
}

func (a *Application) writeFileWithDir(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func (a *Application) backupStore(reason string) (string, error) {
	storeDir := filepath.Join(a.rootPath, "store")
	backupFileName := fmt.Sprintf("store-backup-%s-%s.zip", time.Now().UTC().Format("20060102150405"), reason)
	backupFilePath := filepath.Join(a.rootPath, backupFileName)

	backupFile, err := os.Create(backupFilePath)
	if err != nil {
		return "", err
	}
	defer backupFile.Close()

	zipWriter := zip.NewWriter(backupFile)
	defer zipWriter.Close()

	err = filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(storeDir, path)
		if err != nil {
			return err
		}
		zipFile, err := zipWriter.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()
		_, err = io.Copy(zipFile, fsFile)
		return err
	})

	return backupFilePath, err
}

=== internal/app/application_test.go ===
package app_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"reactor.dev/reactor-ca/internal/app"
	"reactor.dev/reactor-ca/internal/domain"
)

// --- Mocks ---

type mockConfigLoader struct {
	ca    *domain.CAConfig
	hosts *domain.HostsConfig
	err   error
}

func (m *mockConfigLoader) LoadCA() (*domain.CAConfig, error) {
	return m.ca, m.err
}
func (m *mockConfigLoader) LoadHosts() (*domain.HostsConfig, error) {
	return m.hosts, m.err
}

type mockStore struct {
	hostIDs    []string
	deletedIDs []string
	err        error
}

func (m *mockStore) ListHostIDs() ([]string, error) {
	return m.hostIDs, m.err
}
func (m *mockStore) DeleteHost(hostID string) error {
	if m.err != nil {
		return m.err
	}
	m.deletedIDs = append(m.deletedIDs, hostID)
	return nil
}

// Add empty implementations for other Store methods to satisfy the interface
func (m *mockStore) CAExists() (bool, error)                              { return false, nil }
func (m *mockStore) SaveCA(cert, encryptedKey []byte) error               { return nil }
func (m *mockStore) LoadCACert() (*x509.Certificate, error)               { return nil, nil }
func (m *mockStore) LoadCAKey() ([]byte, error)                           { return nil, nil }
func (m *mockStore) HostExists(hostID string) (bool, error)               { return false, nil }
func (m *mockStore) HostKeyExists(hostID string) (bool, error)            { return false, nil }
func (m *mockStore) SaveHostCert(hostID string, cert []byte) error        { return nil }
func (m *mockStore) SaveHostKey(hostID string, encryptedKey []byte) error { return nil }
func (m *mockStore) LoadHostCert(hostID string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockStore) LoadHostKey(hostID string) ([]byte, error)  { return nil, nil }
func (m *mockStore) GetAllEncryptedKeyPaths() ([]string, error) { return nil, nil }
func (m *mockStore) UpdateEncryptedKey(path string, data []byte) error {
	return nil
}
func (m *mockStore) GetHostCertPath(hostID string) string { return "" }
func (m *mockStore) GetHostKeyPath(hostID string) string  { return "" }
func (m *mockStore) GetCACertPath() string                { return "" }

type mockPasswordProvider struct {
	confirmResponse bool
	confirmErr      error
}

func (m *mockPasswordProvider) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, m.confirmErr
}

// Add empty implementations for other PasswordProvider methods
func (m *mockPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}
func (m *mockPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}

type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...interface{})  {}
func (m *mockLogger) Error(msg string, args ...interface{}) {}
func (m *mockLogger) Log(msg string)                        {}

// --- Tests ---

func TestCleanHosts(t *testing.T) {
	errInput := errors.New("input error")

	testCases := []struct {
		name              string
		storeIDs          []string
		configIDs         []string
		force             bool
		confirmResponse   bool
		confirmError      error
		expectedPruned    []string
		expectedErr       error
		expectStoreDelete bool
	}{
		{
			name:           "No hosts to prune",
			storeIDs:       []string{"host1", "host2"},
			configIDs:      []string{"host1", "host2"},
			force:          true,
			expectedPruned: nil,
			expectedErr:    nil,
		},
		{
			name:              "Prune one host with force",
			storeIDs:          []string{"host1", "host2-to-prune"},
			configIDs:         []string{"host1"},
			force:             true,
			expectedPruned:    []string{"host2-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:              "Prune multiple hosts with confirmation",
			storeIDs:          []string{"host1", "host2-to-prune", "host3-to-prune"},
			configIDs:         []string{"host1"},
			force:             false,
			confirmResponse:   true,
			expectedPruned:    []string{"host2-to-prune", "host3-to-prune"},
			expectedErr:       nil,
			expectStoreDelete: true,
		},
		{
			name:            "Prune aborted by user",
			storeIDs:        []string{"host1", "host2-to-prune"},
			configIDs:       []string{"host1"},
			force:           false,
			confirmResponse: false,
			expectedPruned:  nil,
			expectedErr:     domain.ErrActionAborted,
		},
		{
			name:           "Confirmation fails",
			storeIDs:       []string{"host1", "host2-to-prune"},
			configIDs:      []string{"host1"},
			force:          false,
			confirmError:   errInput,
			expectedPruned: nil,
			expectedErr:    errInput,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Mocks
			mockCfgLoader := &mockConfigLoader{
				hosts: &domain.HostsConfig{Hosts: make(map[string]domain.HostConfig)},
			}
			for _, id := range tc.configIDs {
				mockCfgLoader.hosts.Hosts[id] = domain.HostConfig{}
			}

			mockStore := &mockStore{
				hostIDs: tc.storeIDs,
			}

			mockPwProvider := &mockPasswordProvider{
				confirmResponse: tc.confirmResponse,
				confirmErr:      tc.confirmError,
			}

			// Create Application instance
			application := app.NewApplication("", &mockLogger{}, mockCfgLoader, mockStore, nil, mockPwProvider, nil)

			// Run the method
			pruned, err := application.CleanHosts(context.Background(), tc.force)

			// Assertions
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}

			if len(pruned) != len(tc.expectedPruned) {
				t.Fatalf("expected %d pruned hosts, got %d", len(tc.expectedPruned), len(pruned))
			}

			if tc.expectStoreDelete {
				if len(mockStore.deletedIDs) != len(tc.expectedPruned) {
					t.Errorf("expected %d calls to store.DeleteHost, got %d", len(tc.expectedPruned), len(mockStore.deletedIDs))
				}
			} else {
				if len(mockStore.deletedIDs) > 0 {
					t.Errorf("expected no calls to store.DeleteHost, but got %d", len(mockStore.deletedIDs))
				}
			}
		})
	}
}

=== internal/infra/store/filestore.go ===
package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"reactor.dev/reactor-ca/internal/domain"
)

// FileStore implements the domain.Store interface using the local filesystem.
type FileStore struct {
	storePath string
	caPath    string
	hostsPath string
}

const (
	caCertFile   = "ca.crt"
	caKeyFile    = "ca.key.enc"
	hostCertFile = "cert.crt"
	hostKeyFile  = "cert.key.enc"
)

// NewFileStore creates a new filesystem-based store.
func NewFileStore(storePath string) *FileStore {
	return &FileStore{
		storePath: storePath,
		caPath:    filepath.Join(storePath, "ca"),
		hostsPath: filepath.Join(storePath, "hosts"),
	}
}

// Path getters
func (s *FileStore) GetHostCertPath(hostID string) string {
	return filepath.Join(s.hostsPath, hostID, hostCertFile)
}
func (s *FileStore) GetHostKeyPath(hostID string) string {
	return filepath.Join(s.hostsPath, hostID, hostKeyFile)
}
func (s *FileStore) GetCACertPath() string {
	return filepath.Join(s.caPath, caCertFile)
}

// CAExists checks if the CA certificate and key already exist.
func (s *FileStore) CAExists() (bool, error) {
	certPath := s.GetCACertPath()
	keyPath := filepath.Join(s.caPath, caKeyFile)

	certInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	keyInfo, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return certInfo != nil && keyInfo != nil, nil
}

// SaveCA saves the CA certificate and encrypted key to the store.
// If cert or key is nil, it's skipped.
func (s *FileStore) SaveCA(cert, encryptedKey []byte) error {
	if cert != nil {
		if err := os.WriteFile(s.GetCACertPath(), cert, 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate: %w", err)
		}
	}
	if encryptedKey != nil {
		if err := os.WriteFile(filepath.Join(s.caPath, caKeyFile), encryptedKey, 0600); err != nil {
			return fmt.Errorf("failed to write CA key: %w", err)
		}
	}
	return nil
}

// LoadCACert loads the CA public certificate from the store.
func (s *FileStore) LoadCACert() (*x509.Certificate, error) {
	pemData, err := os.ReadFile(s.GetCACertPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrCANotFound
		}
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from ca.crt")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCAKey loads the encrypted CA private key from the store.
func (s *FileStore) LoadCAKey() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.caPath, caKeyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrCANotFound
		}
		return nil, err
	}
	return data, nil
}

// HostExists checks if a directory for the host exists.
func (s *FileStore) HostExists(hostID string) (bool, error) {
	info, err := os.Stat(filepath.Join(s.hostsPath, hostID))
	if os.IsNotExist(err) {
		return false, nil
	}
	return info.IsDir(), err
}

// HostKeyExists checks if the host's private key exists.
func (s *FileStore) HostKeyExists(hostID string) (bool, error) {
	_, err := os.Stat(s.GetHostKeyPath(hostID))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// SaveHostCert saves a host's public certificate.
func (s *FileStore) SaveHostCert(hostID string, cert []byte) error {
	hostDir := filepath.Join(s.hostsPath, hostID)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.GetHostCertPath(hostID), cert, 0644)
}

// SaveHostKey saves a host's encrypted private key.
func (s *FileStore) SaveHostKey(hostID string, encryptedKey []byte) error {
	hostDir := filepath.Join(s.hostsPath, hostID)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.GetHostKeyPath(hostID), encryptedKey, 0600)
}

// LoadHostCert loads a host's public certificate.
func (s *FileStore) LoadHostCert(hostID string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(s.GetHostCertPath(hostID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrHostCertNotFound
		}
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from host cert %s", hostID)
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadHostKey loads a host's encrypted private key.
func (s *FileStore) LoadHostKey(hostID string) ([]byte, error) {
	data, err := os.ReadFile(s.GetHostKeyPath(hostID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrHostKeyNotFound
		}
		return nil, err
	}
	return data, nil
}

// ListHostIDs returns a slice of all host IDs (directory names) in the store.
func (s *FileStore) ListHostIDs() ([]string, error) {
	entries, err := os.ReadDir(s.hostsPath)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}

// DeleteHost removes a host's directory from the store.
func (s *FileStore) DeleteHost(hostID string) error {
	return os.RemoveAll(filepath.Join(s.hostsPath, hostID))
}

// GetAllEncryptedKeyPaths finds all *.key.enc files in the store.
func (s *FileStore) GetAllEncryptedKeyPaths() ([]string, error) {
	var paths []string

	// CA key
	caKeyPath := filepath.Join(s.caPath, caKeyFile)
	if _, err := os.Stat(caKeyPath); err == nil {
		paths = append(paths, caKeyPath)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Host keys
	hostIDs, err := s.ListHostIDs()
	if err != nil {
		return nil, err
	}
	for _, id := range hostIDs {
		hostKeyPath := s.GetHostKeyPath(id)
		if _, err := os.Stat(hostKeyPath); err == nil {
			paths = append(paths, hostKeyPath)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return paths, nil
}

// UpdateEncryptedKey writes new data to an existing key file path.
// It uses an atomic write-and-rename operation for safety.
func (s *FileStore) UpdateEncryptedKey(path string, data []byte) (err error) {
	// Create a temporary file in the same directory to ensure atomic rename.
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary key file: %w", err)
	}
	// Ensure the temp file is removed on error
	defer func() {
		if err != nil {
			os.Remove(tmpFile.Name())
		}
	}()

	if err = os.Chmod(tmpFile.Name(), 0600); err != nil {
		return fmt.Errorf("failed to set permissions on temporary key file: %w", err)
	}

	if _, err = tmpFile.Write(data); err != nil {
		_ = tmpFile.Close() // Close file before trying to remove.
		return fmt.Errorf("failed to write to temporary key file: %w", err)
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary key file: %w", err)
	}

	// Atomically replace the old file with the new one.
	err = os.Rename(tmpFile.Name(), path)
	if err != nil {
		return fmt.Errorf("failed to rename temporary key file to final destination: %w", err)
	}

	return nil
}

---
Tokens: 42402 input, 21428 output, 73125 total
Cost: $0.053002 input + $0.214280 output = $0.267282 total
