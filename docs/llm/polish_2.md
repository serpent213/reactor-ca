you are a senior Go engineer with a lot of experience with encryption and security and a faible for CLI/text-based user interfaces/UX, especially X.509 PKI management. review the following home-lab/SOHO CLI CA implementation with regards to

- consistent error handling with good UX
- consistent UI output and `ui` functions usage
- package naming, structure and responsibilities (also in tests!)
- gaping holes in test coverage
- opportunity for shared test setup helpers, unified mocking strategy
- split between unit tests (with mocks) and integration tests (using external tools to create valid keys/test data)
- code smells
- deprecated/legacy code
- easy refactorings for simplification

return only a summarised review and a set of grouped refactoring suggestions (if required)!

if you want to update/create files, mark output files with `=== $filename ===`, as we do in the input, and bundle them at the end of your response.

current implementation:

--- LLM Response ---
As a senior Go engineer, I've reviewed your `ReactorCA` project. Overall, this is an impressive piece of work for a homelab/SOHO tool. It exhibits a high degree of quality, thoughtful design, and attention to security and user experience. The use of a clean architecture (`domain`/`app`/`infra`) is excellent and pays dividends in clarity and testability. The choice of `age` for key encryption is modern and robust, and the CLI itself is well-structured and user-friendly.

### Summarised Review

*   **Strengths**:
    *   **Architecture**: The hexagonal (ports and adapters) architecture is well-implemented, creating a clear separation of concerns.
    *   **Security**: Strong, modern cryptographic choices are made. The implementation includes critical security best practices like atomic file writes for keys, secure temp file handling, and clear warnings for destructive operations.
    *   **CLI/UX**: The command structure is logical. The UI is consistent in most places, with helpful colored output, progress indicators, and interactive confirmations. The `processHostCmd` helper for batch operations is a standout feature.
    *   **Code Quality**: The code is generally clean, idiomatic Go. Helper functions and patterns like `withCAKey` effectively reduce boilerplate.
    *   **Testing**: The end-to-end (E2E) integration tests are excellent. They are well-structured, use external validation (`openssl`), and cover the main user workflows effectively.

*   **Areas for Improvement**:
    *   **Unit Test Coverage**: There's a significant lack of unit tests for the core application logic in the `internal/app` package. While the E2E tests provide a safety net, unit tests are needed to efficiently test edge cases and error paths.
    *   **Consistency**: Minor inconsistencies exist in UI output (mixing `fmt.Println` with `ui` package functions) and command implementation (unused flag variables).
    *   **Minor Code Smells**: The main `Application` struct is large and could be considered a "god object," a candidate for being broken into smaller, more focused services. The dependency injection in `root.go` is also quite complex.

The project is already very strong. The following suggestions are aimed at refining an already great foundation, primarily by bolstering test coverage and improving consistency.

### Refactoring Suggestions

Here is a set of proposed refactorings, grouped by theme. The accompanying files implement the most direct and impactful of these suggestions.

#### Group 1: UI & UX Consistency

1.  **Standardize All Command Output**: Commands that print raw text blocks (like `ca info` and `host info`) currently use `fmt.Println`, bypassing the `ui` package. This should be standardized for consistency.
    *   **Action**: Create a new `ui.PrintBlock()` function and refactor the `info` commands to use it.
2.  **Unify Action Messages**: The `processHostCmd` helper uses `fmt.Printf` to display action messages, which is slightly inconsistent with the `ui.Action` function used elsewhere.
    *   **Action**: Update `processHostCmd` to use `ui.Action` for all progress messages.
3.  **Remove Unused Code**: The `host issue` and `host deploy` commands declare global variables for the `--all` flag (`issueAllHosts`, `deployAllHosts`) that are never used.
    *   **Action**: Remove the unused variables and change the flag registration from `BoolVar` to `Bool`.

#### Group 2: Testing Strategy & Coverage

1.  **Add Unit Tests for Application Logic**: The most critical area for improvement is adding unit tests for the `app.Application` methods to cover logic and error paths that are cumbersome to hit with E2E tests.
    *   **Action**: Add a new test file, `internal/app/issue_host_test.go`, to demonstrate how to test the `IssueHost` use case. This will serve as a template for adding more coverage.
2.  **Create Shared Test Helpers**: The unit tests for the `app` layer require extensive mocking. This setup can be shared to make writing new tests easier.
    *   **Action**: Create a new `internal/app/testhelper` package. This package will contain reusable mocks and a setup function (`SetupTestApplication`) to initialize the application with mocked dependencies for testing.

---

### File Updates

Here are the new and updated files that implement the refactoring suggestions.

=== internal/ui/output.go ===
```go
package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Color functions for consistent styling
var (
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// Success prints a success message with green ✓ symbol
func Success(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", green("✓"), formatted)
}

// Error prints an error message with red ✗ symbol
func Error(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", red("✗"), formatted)
}

// Warning prints a warning message with yellow ! symbol
func Warning(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", yellow("!"), formatted)
}

// Info prints an info message with cyan i symbol
func Info(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", cyan("i"), formatted)
}

// Action prints an action/progress message with cyan → symbol
func Action(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", cyan("→"), formatted)
}

// PrintBlock prints a block of pre-formatted text, such as certificate details.
// This ensures all command output goes through the UI package for consistency.
func PrintBlock(text string) {
	fmt.Println(text)
}

// PrintTableHeader prints a styled table header with border
func PrintTableHeader(columns ...string) {
	header := strings.Join(columns, " | ")
	fmt.Printf("%s\n", bold(cyan(header)))
	fmt.Println(cyan(strings.Repeat("─", len(header))))
}

// FormatCertStatus returns a formatted certificate status with appropriate symbol and color
func FormatCertStatus(daysRemaining int64) string {
	if daysRemaining < 0 {
		return red("✗") + " EXPIRED"
	} else if daysRemaining < 7 {
		return red("✗") + fmt.Sprintf(" %d days", daysRemaining)
	} else if daysRemaining < 30 {
		return yellow("!") + fmt.Sprintf(" %d days", daysRemaining)
	} else {
		return green("✓") + fmt.Sprintf(" %d days", daysRemaining)
	}
}

// GetColoredLogo returns the ReactorCA ASCII art logo with Reactor in cyan and CA in gray
func GetColoredLogo() string {
	gray := color.New(color.FgHiBlack).SprintFunc()

	// Split each line at the boundary between "Reactor" and "CA"
	lines := []struct{ left, right string }{
		{" ______                                    ", "______"},
		{"(_____ \\                  _               ", "/ _____)  /\\"},
		{" _____) ) ____ ____  ____| |_  ___   ____", "| /       /  \\"},
		{"(_____ ( / _  ) _  |/ ___)  _)/ _ \\ / ___) ", "|      / /\\ \\"},
		{"      | ( (/ ( ( | ( (___| |_| |_| | |   ", "| \\_____| |__| |"},
		{"      |_|\\____)_||_|\\____)\\___}___/|_|    ", "\\______)______|"},
	}

	var result strings.Builder
	for _, line := range lines {
		result.WriteString(cyan(line.left) + gray(line.right) + "\n")
	}

	return result.String()
}
```
=== cmd/ca/commands/ca.go ===
```go
package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/ui"
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
		ui.Success("CA created successfully")
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
		ui.Success("CA renewed successfully")
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
		ui.Success("CA re-keyed successfully. Remember to re-issue all host certificates")
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
		ui.PrintBlock(info)
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
		ui.Success("CA imported successfully")
		return nil
	},
}

// ca reencrypt
var caReencryptCmd = &cobra.Command{
	Use:   "reencrypt",
	Short: "Re-encrypt all keys with new password or updated recipients",
	Long: strings.TrimSpace(`
Re-encrypt all private keys in the store with new encryption parameters:
- For password encryption: change the master password
- For SSH/plugin encryption: update recipient lists

A round-trip validation test is performed to ensure you can decrypt
the re-encrypted keys. Use --force to bypass validation failures.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")
		err := app.ReencryptKeys(cmd.Context(), force)
		if err != nil {
			return err
		}
		ui.Success("All keys re-encrypted successfully")
		return nil
	},
}

func init() {
	caImportCmd.Flags().StringVar(&importCertPath, "cert", "", "Path to the CA certificate file (PEM format)")
	caImportCmd.Flags().StringVar(&importKeyPath, "key", "", "Path to the CA private key file (PEM format)")
	_ = caImportCmd.MarkFlagRequired("cert")
	_ = caImportCmd.MarkFlagRequired("key")

	caRekeyCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	caReencryptCmd.Flags().Bool("force", false, "Skip round-trip validation")

	caCmd.AddCommand(caCreateCmd)
	caCmd.AddCommand(caRenewCmd)
	caCmd.AddCommand(caRekeyCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caImportCmd)
	caCmd.AddCommand(caReencryptCmd)
}
```
=== cmd/ca/commands/helpers.go ===
```go
package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/ui"
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
			ui.Info("No hosts found in configuration.")
			return nil
		}
		ui.Action(pluralActionMsg, len(hostIDs))
	} else {
		hostIDs = append(hostIDs, args[0])
	}

	var hasErrors bool
	for _, id := range hostIDs {
		// Only print the singular action message if we are not in "all" mode,
		// as the plural message has already been printed.
		if !isAll {
			ui.Action(singularActionMsg, id)
		}
		err := actionFunc(cmd.Context(), id)
		if err != nil {
			hasErrors = true
			// Don't stop on error if --all is used
			if isAll {
				ui.Error("Error processing host '%s': %v", id, err)
				continue
			}
			return err
		}
		if successMsg != "" {
			ui.Success(successMsg, id)
		}
	}

	if isAll {
		fmt.Println()
		if hasErrors {
			ui.Warning("Done, but with errors")
		} else {
			ui.Success("Done")
		}
	}
	return nil
}
```
=== cmd/ca/commands/host.go ===
```go
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/ui"
)

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Manage host certificates",
}

// host issue
var (
	rekeyHost  bool
	deployHost bool
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
			"Successfully issued certificate for '%s'",
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
		ui.Info("No host certificates found in the store.")
		return
	}

	// Header
	ui.PrintTableHeader("HOST ID", "EXPIRES (UTC)", "STATUS / DAYS REMAINING")

	for _, h := range list {
		fmt.Printf("%-30s | %-25s | %s\n",
			h.ID,
			h.NotAfter.UTC().Format(time.RFC3339),
			ui.FormatCertStatus(h.DaysRemaining))
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
		ui.PrintBlock(info)
		return nil
	},
}

// host deploy
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
			"Successfully deployed certificate for '%s'",
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
			ui.Success("Unencrypted key for '%s' exported to %s", hostID, exportKeyOutPath)
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
		ui.Success("Key for host '%s' imported successfully. Run 'host issue %s' to create a matching certificate", args[0], args[0])
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
			ui.Success("Certificate signed successfully and saved to %s", csrOut)
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
			ui.Info("Store is already clean. No hosts to prune.")
			return nil
		}

		ui.Success("Pruned the following hosts from the store:")
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
	hostIssueCmd.Flags().Bool("all", false, "Issue certificates for all hosts defined in hosts.yaml")
	hostCmd.AddCommand(hostIssueCmd)

	// host list
	hostListCmd.Flags().BoolVar(&listExpired, "expired", false, "Only show expired certificates")
	hostListCmd.Flags().IntVar(&listExpiringIn, "expiring-in", 0, "Only show certificates expiring in the next N days")
	hostListCmd.Flags().BoolVar(&listJSON, "json", false, "Output the list in JSON format")
	hostCmd.AddCommand(hostListCmd)

	// host info
	hostCmd.AddCommand(hostInfoCmd)

	// host deploy
	hostDeployCmd.Flags().Bool("all", false, "Deploy certificates for all hosts with a deploy command")
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
```
=== internal/app/testhelper/helper.go ===
```go
package testhelper

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/crypto"
)

// --- Mocks for Dependencies ---

type MockConfigLoader struct {
	CAConfig    *domain.CAConfig
	HostsConfig *domain.HostsConfig
	Err         error
}

func (m *MockConfigLoader) LoadCA() (*domain.CAConfig, error)    { return m.CAConfig, m.Err }
func (m *MockConfigLoader) LoadHosts() (*domain.HostsConfig, error) { return m.HostsConfig, m.Err }

type MockStore struct {
	SaveCAFunc           func(cert, key []byte) error
	SaveHostCertFunc     func(hostID string, cert []byte) error
	SaveHostKeyFunc      func(hostID string, encryptedKey []byte) error
	LoadCACertFunc       func() (*x509.Certificate, error)
	LoadHostKeyFunc      func(hostID string) ([]byte, error)
	HostKeyExistsMap     map[string]bool
	HostKeyExistsErr     error
	DeleteHostFunc       func(hostID string) error
	ListHostIDsFunc      func() ([]string, error)
	GetAllKeysFunc       func() ([]string, error)
	UpdateEncryptedKeyFunc func(path string, data []byte) error
}

func (m *MockStore) CAExists() (bool, error)                { return false, nil }
func (m *MockStore) SaveCA(c, k []byte) error               { return m.SaveCAFunc(c, k) }
func (m *MockStore) LoadCACert() (*x509.Certificate, error) { return m.LoadCACertFunc() }
func (m *MockStore) LoadCAKey() ([]byte, error)             { return nil, nil }
func (m *MockStore) HostExists(hostID string) (bool, error) { return false, nil }
func (m *MockStore) HostKeyExists(hostID string) (bool, error) {
	return m.HostKeyExistsMap[hostID], m.HostKeyExistsErr
}
func (m *MockStore) SaveHostCert(id string, c []byte) error    { return m.SaveHostCertFunc(id, c) }
func (m *MockStore) SaveHostKey(id string, k []byte) error     { return m.SaveHostKeyFunc(id, k) }
func (m *MockStore) LoadHostCert(id string) (*x509.Certificate, error) { return nil, nil }
func (m *MockStore) LoadHostKey(id string) ([]byte, error)     { return m.LoadHostKeyFunc(id) }
func (m *MockStore) ListHostIDs() ([]string, error)            { return m.ListHostIDsFunc() }
func (m *MockStore) DeleteHost(id string) error                { return m.DeleteHostFunc(id) }
func (m *MockStore) GetAllEncryptedKeyPaths() ([]string, error) { return m.GetAllKeysFunc() }
func (m *MockStore) UpdateEncryptedKey(p string, d []byte) error {
	return m.UpdateEncryptedKeyFunc(p, d)
}
func (m *MockStore) GetHostCertPath(id string) string { return "" }
func (m *MockStore) GetHostKeyPath(id string) string  { return "" }
func (m *MockStore) GetCACertPath() string            { return "" }

type MockCryptoService struct {
	domain.CryptoService
	GeneratePrivateKeyFunc  func(algo domain.KeyAlgorithm) (crypto.Signer, error)
	EncryptPrivateKeyFunc   func(key crypto.Signer, password []byte) ([]byte, error)
	DecryptPrivateKeyFunc   func(pemData, password []byte) (crypto.Signer, error)
	CreateHostCertificateFunc func(hostCfg *domain.HostConfig, caCert *x509.Certificate, caKey crypto.Signer, hostPublicKey crypto.PublicKey) (*x509.Certificate, error)
	EncodeCertificateToPEMFunc func(cert *x509.Certificate) []byte
}

func (m *MockCryptoService) GeneratePrivateKey(a domain.KeyAlgorithm) (crypto.Signer, error) {
	return m.GeneratePrivateKeyFunc(a)
}
func (m *MockCryptoService) EncryptPrivateKey(k crypto.Signer, p []byte) ([]byte, error) {
	return m.EncryptPrivateKeyFunc(k, p)
}
func (m *MockCryptoService) DecryptPrivateKey(d, p []byte) (crypto.Signer, error) {
	return m.DecryptPrivateKeyFunc(d, p)
}
func (m *MockCryptoService) CreateHostCertificate(h *domain.HostConfig, c *x509.Certificate, k crypto.Signer, p crypto.PublicKey) (*x509.Certificate, error) {
	return m.CreateHostCertificateFunc(h, c, k, p)
}
func (m *MockCryptoService) EncodeCertificateToPEM(c *x509.Certificate) []byte {
    return m.EncodeCertificateToPEMFunc(c)
}

type MockPasswordProvider struct {
	MasterPassword    []byte
	MasterPasswordErr error
}

func (m *MockPasswordProvider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	return m.MasterPassword, m.MasterPasswordErr
}
func (m *MockPasswordProvider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}
func (m *MockPasswordProvider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	return nil, nil
}

type MockCommander struct {
	ExecuteErr error
}

func (m *MockCommander) Execute(name string, args ...string) ([]byte, error) {
	return []byte("ok"), m.ExecuteErr
}

type MockLogger struct{}

func (m *MockLogger) Info(msg string, args ...interface{})  {}
func (m *MockLogger) Error(msg string, args ...interface{}) {}
func (m *MockLogger) Log(msg string)                        {}

// --- Test Setup Helper ---

// Mocks contains all the mockable dependencies for the Application.
type Mocks struct {
	ConfigLoader *MockConfigLoader
	Store        *MockStore
	CryptoSvc    *MockCryptoService
	Password     *MockPasswordProvider
	Commander    *MockCommander
	Logger       *MockLogger
}

// SetupTestApplication initializes the Application service with mocks for unit testing.
func SetupTestApplication(t *testing.T) (*app.Application, *Mocks) {
	t.Helper()

	mocks := &Mocks{
		ConfigLoader: &MockConfigLoader{},
		Store:        &MockStore{},
		CryptoSvc:    &MockCryptoService{CryptoService: crypto.NewService()},
		Password:     &MockPasswordProvider{},
		Commander:    &MockCommander{},
		Logger:       &MockLogger{},
	}

	// Use real crypto service for cert generation, but allow overriding specific functions.
	// This makes it easy to test logic without mocking all of crypto.
	realCryptoSvc := crypto.NewService()
	mocks.CryptoSvc.CreateHostCertificateFunc = realCryptoSvc.CreateHostCertificate
	mocks.CryptoSvc.EncodeCertificateToPEMFunc = realCryptoSvc.EncodeCertificateToPEM

	application := app.NewApplication(
		"/test/root",
		mocks.Logger,
		mocks.ConfigLoader,
		mocks.Store,
		mocks.CryptoSvc,
		mocks.Password,
		nil, // UserInteraction
		mocks.Commander,
		nil, // IdentityProvider
		nil, // IdentityProviderFactory
		nil, // CryptoServiceFactory
		nil, // ValidationService
	)

	return application, mocks
}

// --- Common Test Data ---

func GetTestCAConfig() *domain.CAConfig {
	return &domain.CAConfig{
		CA: struct {
			Subject       domain.SubjectConfig `yaml:"subject"`
			Validity      domain.Validity      `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm  `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm `yaml:"hash_algorithm"`
		}{
			Subject:      domain.SubjectConfig{CommonName: "Test CA"},
			Validity:     domain.Validity{Years: 1},
			KeyAlgorithm: domain.ECP256,
		},
		Encryption: domain.EncryptionConfig{Provider: "password"},
	}
}

func GetTestHostsConfig(hostID string) *domain.HostsConfig {
	return &domain.HostsConfig{
		Hosts: map[string]domain.HostConfig{
			hostID: {
				Subject:      domain.SubjectConfig{CommonName: hostID + ".test.com"},
				Validity:     domain.Validity{Days: 90},
				KeyAlgorithm: domain.RSA2048,
			},
		},
	}
}

func GetTestCACert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	// Use the real crypto service to generate a valid CA cert for tests
	svc := crypto.NewService()
	key, err := svc.GeneratePrivateKey(domain.ECP256)
	if err != nil {
		t.Fatalf("Failed to generate test CA key: %v", err)
	}
	cert, err := svc.CreateRootCertificate(&domain.CAConfig{
		CA: struct {
			Subject       domain.SubjectConfig `yaml:"subject"`
			Validity      domain.Validity      `yaml:"validity"`
			KeyAlgorithm  domain.KeyAlgorithm  `yaml:"key_algorithm"`
			HashAlgorithm domain.HashAlgorithm `yaml:"hash_algorithm"`
		}{
			Subject:  domain.SubjectConfig{CommonName: "Test CA"},
			Validity: domain.Validity{Years: 1},
		},
	}, key)
	if err != nil {
		t.Fatalf("Failed to generate test CA cert: %v", err)
	}
	return cert, key
}

func GetTestError() error {
	return errors.New("something went wrong")
}

var DummyPassword = []byte("test-password")
var DummyEncryptedKey = []byte("age-encrypted-key-data")
var DummyCertPEM = []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
```
=== internal/app/issue_host_test.go ===
```go
package app_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"reactor.de/reactor-ca/internal/app/testhelper"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/crypto"
)

func TestIssueHost_NewHost(t *testing.T) {
	// Arrange
	const hostID = "web-server"
	app, mocks := testhelper.SetupTestApplication(t)
	testCAConfig := testhelper.GetTestCAConfig()
	testHostsConfig := testhelper.GetTestHostsConfig(hostID)
	testCACert, testCAKey := testhelper.GetTestCACert(t)

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = testhelper.DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) {
		return testCACert, nil
	}
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: false} // Key does not exist
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		// Use real crypto service for this
		return crypto.NewService().GeneratePrivateKey(algo)
	}
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(key crypto.Signer, password []byte) ([]byte, error) {
		return testhelper.DummyEncryptedKey, nil
	}
	mocks.Store.SaveHostKeyFunc = func(id string, encryptedKey []byte) error {
		if id != hostID {
			t.Errorf("expected to save key for host '%s', got '%s'", hostID, id)
		}
		if string(encryptedKey) != string(testhelper.DummyEncryptedKey) {
			t.Errorf("unexpected encrypted key data saved")
		}
		return nil
	}
	mocks.Store.SaveHostCertFunc = func(id string, cert []byte) error {
		if id != hostID {
			t.Errorf("expected to save cert for host '%s', got '%s'", hostID, id)
		}
		return nil
	}
	// Use real function to decrypt the CA key
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d, p []byte) (crypto.Signer, error) { return testCAKey, nil }

	// Act
	err := app.IssueHost(context.Background(), hostID, false, false)

	// Assert
	if err != nil {
		t.Fatalf("IssueHost failed: %v", err)
	}
	// Assertions are performed inside the mock functions
}

func TestIssueHost_RenewHost(t *testing.T) {
	// Arrange
	const hostID = "db-server"
	app, mocks := testhelper.SetupTestApplication(t)
	testCAConfig := testhelper.GetTestCAConfig()
	testHostsConfig := testhelper.GetTestHostsConfig(hostID)
	testCACert, testCAKey := testhelper.GetTestCACert(t)
	// Use real crypto service to generate a realistic host key
	realCrypto := crypto.NewService()
	existingHostKey, _ := realCrypto.GeneratePrivateKey(domain.ECP256)

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = testhelper.DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: true} // Key EXISTS
	mocks.Store.LoadHostKeyFunc = func(id string) ([]byte, error) {
		return testhelper.DummyEncryptedKey, nil // Return some dummy encrypted data
	}
	// Decrypt should return our known host key
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(data, password []byte) (crypto.Signer, error) {
		// The first call will be to decrypt the CA key, second for the host key
		if string(data) == string(testhelper.DummyEncryptedKey) {
			return existingHostKey, nil
		}
		return testCAKey, nil
	}
	var generatedKeyForRekey crypto.Signer
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		// This should NOT be called when renewing without --rekey
		t.Error("GeneratePrivateKey should not be called when renewing an existing host")
		// but we still return a value to not panic
		generatedKeyForRekey, _ = realCrypto.GeneratePrivateKey(algo)
		return generatedKeyForRekey, nil
	}
	mocks.Store.SaveHostCertFunc = func(id string, cert []byte) error { return nil } // We expect this to be called

	// Act
	err := app.IssueHost(context.Background(), hostID, false, false) // rekey=false

	// Assert
	if err != nil {
		t.Fatalf("IssueHost for renewal failed: %v", err)
	}
	if generatedKeyForRekey != nil {
		t.Error("A new key was generated for a simple renewal, which is incorrect.")
	}
}

func TestIssueHost_RekeyHost(t *testing.T) {
	// Arrange
	const hostID = "api-server"
	app, mocks := testhelper.SetupTestApplication(t)
	testCAConfig := testhelper.GetTestCAConfig()
	testHostsConfig := testhelper.GetTestHostsConfig(hostID)
	testCACert, testCAKey := testhelper.GetTestCACert(t)
	realCrypto := crypto.NewService()
	var newKeyGenerated bool

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = testhelper.DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: true} // Key exists, but we will rekey
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(algo domain.KeyAlgorithm) (crypto.Signer, error) {
		newKeyGenerated = true
		return realCrypto.GeneratePrivateKey(algo)
	}
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(k, p []byte) ([]byte, error) { return testhelper.DummyEncryptedKey, nil }
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d, p []byte) (crypto.Signer, error) { return testCAKey, nil } // Only CA key is decrypted
	mocks.Store.SaveHostKeyFunc = func(id string, k []byte) error { return nil }
	mocks.Store.SaveHostCertFunc = func(id string, c []byte) error { return nil }

	// Act
	err := app.IssueHost(context.Background(), hostID, true, false) // rekey=true

	// Assert
	if err != nil {
		t.Fatalf("IssueHost with rekey failed: %v", err)
	}
	if !newKeyGenerated {
		t.Error("Expected a new key to be generated with --rekey, but it wasn't")
	}
}

func TestIssueHost_Deploy(t *testing.T) {
	// Arrange
	const hostID = "deploy-target"
	app, mocks := testhelper.SetupTestApplication(t)
	testCAConfig := testhelper.GetTestCAConfig()
	testHostsConfig := testhelper.GetTestHostsConfig(hostID)
	// Add deploy commands to config
	testHostsConfig.Hosts[hostID] = domain.HostConfig{
		Subject:      domain.SubjectConfig{CommonName: "deploy.test.com"},
		Validity:     domain.Validity{Days: 1},
		KeyAlgorithm: domain.ECP256,
		Deploy:       domain.DeployConfig{Commands: []string{"echo deployed"}},
	}
	testCACert, testCAKey := testhelper.GetTestCACert(t)
	realCrypto := crypto.NewService()
	hostKey, _ := realCrypto.GeneratePrivateKey(domain.ECP256)
	var commanderCalled bool

	// --- Mock setup ---
	mocks.ConfigLoader.CAConfig = testCAConfig
	mocks.ConfigLoader.HostsConfig = testHostsConfig
	mocks.Password.MasterPassword = testhelper.DummyPassword
	mocks.Store.LoadCACertFunc = func() (*x509.Certificate, error) { return testCACert, nil }
	mocks.Store.HostKeyExistsMap = map[string]bool{hostID: false}
	mocks.CryptoSvc.GeneratePrivateKeyFunc = func(a domain.KeyAlgorithm) (crypto.Signer, error) { return hostKey, nil }
	mocks.CryptoSvc.EncryptPrivateKeyFunc = func(k, p []byte) ([]byte, error) { return testhelper.DummyEncryptedKey, nil }
	mocks.CryptoSvc.DecryptPrivateKeyFunc = func(d, p []byte) (crypto.Signer, error) {
		// 1st decrypt CA key, 2nd decrypt host key for deploy
		if string(d) == "" { // simple heuristic for test
			return testCAKey, nil
		}
		return hostKey, nil
	}
	mocks.Store.LoadHostKeyFunc = func(id string) ([]byte, error) { return testhelper.DummyEncryptedKey, nil } // for deploy step
	mocks.Store.SaveHostKeyFunc = func(id string, k []byte) error { return nil }
	mocks.Store.SaveHostCertFunc = func(id string, c []byte) error { return nil }
	mocks.Commander.Execute = func(name string, args ...string) ([]byte, error) {
		commanderCalled = true
		return nil, nil
	}

	// Act
	err := app.IssueHost(context.Background(), hostID, false, true) // deploy=true

	// Assert
	if err != nil {
		t.Fatalf("IssueHost with deploy failed: %v", err)
	}
	if !commanderCalled {
		t.Error("Expected commander to be executed for deployment, but it wasn't")
	}
}
```

---
Tokens: 60197 input, 12079 output, 79996 total
Cost: $0.075246 input + $0.120790 output = $0.196036 total
