package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	Args: func(cmd *cobra.Command, args []string) error {
		if !issueAllHosts && len(args) != 1 {
			return fmt.Errorf("accepts exactly one argument: <host-id>")
		}
		if issueAllHosts && len(args) > 0 {
			return fmt.Errorf("cannot use <host-id> argument when --all is specified")
		}
		if !issueAllHosts && len(args) == 0 {
			return fmt.Errorf("must specify <host-id> or use --all flag")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)

		var hostIDs []string
		if issueAllHosts {
			var err error
			hostIDs, err = appCtx.App.GetAllHostIDs(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("Issuing certificates for all %d hosts...\n", len(hostIDs))
		} else {
			hostIDs = append(hostIDs, args[0])
		}

		for _, id := range hostIDs {
			fmt.Printf("Issuing certificate for host '%s'...\n", id)
			err := appCtx.App.IssueHost(cmd.Context(), id, rekeyHost, deployHost)
			if err != nil {
				// Don't stop on error if --all is used
				if issueAllHosts {
					color.Red("  Error: %v\n", err)
					continue
				}
				return err
			}
			color.Green("  ✅ Successfully issued certificate for '%s'\n", id)
		}

		fmt.Println("\nDone.")
		return nil
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		list, err := appCtx.App.ListHosts(cmd.Context())
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
		daysStr := strconv.FormatInt(h.DaysRemaining, 10)
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		info, err := appCtx.App.InfoHost(cmd.Context(), args[0])
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
	Args: func(cmd *cobra.Command, args []string) error {
		if !deployAllHosts && len(args) != 1 {
			return fmt.Errorf("accepts exactly one argument: <host-id>")
		}
		if deployAllHosts && len(args) > 0 {
			return fmt.Errorf("cannot use <host-id> argument when --all is specified")
		}
		if !deployAllHosts && len(args) == 0 {
			return fmt.Errorf("must specify <host-id> or use --all flag")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		var hostIDs []string
		if deployAllHosts {
			var err error
			hostIDs, err = appCtx.App.GetAllHostIDs(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("Deploying certificates for all %d hosts...\n", len(hostIDs))
		} else {
			hostIDs = append(hostIDs, args[0])
		}

		for _, id := range hostIDs {
			fmt.Printf("Deploying certificate for host '%s'...\n", id)
			err := appCtx.App.DeployHost(cmd.Context(), id)
			if err != nil {
				if deployAllHosts {
					color.Red("  Error: %v\n", err)
					continue
				}
				return err
			}
			color.Green("  ✅ Successfully deployed certificate for '%s'\n", id)
		}

		fmt.Println("\nDone.")
		return nil
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		pemKey, err := appCtx.App.ExportHostKey(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		if exportKeyOutPath == "" || exportKeyOutPath == "-" {
			fmt.Print(string(pemKey))
		} else {
			if err := os.WriteFile(exportKeyOutPath, pemKey, 0600); err != nil {
				return fmt.Errorf("failed to write key to %s: %w", exportKeyOutPath, err)
			}
			fmt.Printf("✅ Unencrypted key for '%s' exported to %s\n", args[0], exportKeyOutPath)
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ImportHostKey(cmd.Context(), args[0], importHostKeyPath)
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		certPEM, err := appCtx.App.SignCSR(cmd.Context(), csrPath, csrDays)
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		pruned, err := appCtx.App.CleanHosts(cmd.Context(), forceClean)
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
