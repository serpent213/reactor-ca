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

			// First, resolve and validate the host configuration
			_, err := app.ResolveHostConfig(hostID, rekeyHost)
			if err != nil {
				return err
			}

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
		if !listJSON {
			ui.Action("Listing host certificates from store")
		}
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
		ui.Info("No hosts found.")
		return
	}

	table := ui.NewHostsTable()

	// Set headers
	table.Header([]string{"HOST ID", "KEY ALGO", "KEY LEN", "HASH ALGO", "EXPIRES (UTC)", "STATUS / DAYS REMAINING"})

	// Prepare data rows
	var data [][]string
	for _, h := range list {
		var expiresStr, statusStr, keyAlgoStr, keyLenStr, hashAlgoStr string

		if h.Status == domain.HostStatusConfigured {
			expiresStr = "-"
			statusStr = ui.FormatHostStatus(string(h.Status))
			keyAlgoStr = "-"
			keyLenStr = "-"
			hashAlgoStr = "-"
		} else if h.Status == domain.HostStatusOrphaned {
			expiresStr = h.NotAfter.UTC().Format(time.RFC3339)
			statusStr = ui.FormatHostStatus(string(h.Status))
			keyAlgoStr = h.KeyAlgorithm
			keyLenStr = fmt.Sprintf("%d", h.KeyLength)
			hashAlgoStr = h.HashAlgorithm
		} else {
			// Issued hosts show normal certificate expiry info
			expiresStr = h.NotAfter.UTC().Format(time.RFC3339)
			statusStr = ui.FormatCertStatus(h.DaysRemaining)
			keyAlgoStr = h.KeyAlgorithm
			keyLenStr = fmt.Sprintf("%d", h.KeyLength)
			hashAlgoStr = h.HashAlgorithm
		}

		data = append(data, []string{
			h.ID,
			keyAlgoStr,
			keyLenStr,
			hashAlgoStr,
			expiresStr,
			statusStr,
		})
	}

	// Add data and footer
	table.Bulk(data)
	table.Footer([]string{"", "", "", "", "Total", fmt.Sprintf("%d", len(list))})
	table.Render()
}

// host info
var hostInfoCmd = &cobra.Command{
	Use:   "info <host-id>",
	Short: "Display detailed information about a specific host certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Action("Retrieving certificate information for host '%s'", args[0])
		app := getApp(cmd)
		cert, err := app.InfoHost(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		ui.PrintCertInfo(cert)
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
		ui.Action("Exporting unencrypted private key for host '%s'", args[0])
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
		ui.Action("Importing private key for host '%s' from %s", args[0], importHostKeyPath)
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
		ui.Action("Signing external CSR from %s (valid for %d days)", csrPath, csrDays)
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
		ui.Action("Cleaning orphaned certificates from store")
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
