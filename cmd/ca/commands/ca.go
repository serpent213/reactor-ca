package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/domain"
	"reactor.de/reactor-ca/internal/infra/exec"
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
	Long: strings.TrimSpace(`
Create a new CA key and self-signed certificate.

A round-trip validation test is performed to ensure you can decrypt
the newly created CA key. Use --force to bypass validation failures.`),
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.Action("Creating new CA certificate and private key")
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")

		// Validate CA configuration
		err := app.ValidateCAConfig(false)
		if err != nil {
			return err
		}

		err = app.CreateCA(cmd.Context(), force)
		if err != nil {
			if err == domain.ErrCAAlreadyExists {
				return fmt.Errorf("%w\n%s", err, "Hint: To replace the existing CA, use “ca ca rekey”.")
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
		ui.Action("Renewing CA certificate with existing private key")
		app := getApp(cmd)

		// Validate CA configuration
		err := app.ValidateCAConfig(false)
		if err != nil {
			return err
		}

		err = app.RenewCA(cmd.Context())
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

		// Validate CA configuration (skip key warnings since rekey will fix them)
		err := app.ValidateCAConfig(true)
		if err != nil {
			return err
		}

		ui.Action("Creating new CA private key and certificate (re-key operation)")
		err = app.RekeyCA(cmd.Context(), force)
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
		openssl, _ := cmd.Flags().GetBool("openssl")
		if openssl {
			return exec.ExecOpenSSLCertInfo(getApp(cmd).GetStore().GetCACertPath())
		}

		ui.Action("Retrieving CA certificate information")
		app := getApp(cmd)
		cert, err := app.InfoCA(cmd.Context())
		if err != nil {
			return err
		}

		// Get warning thresholds from config
		caCfg, err := app.GetCAConfig()
		if err != nil {
			// Use domain defaults if config can't be loaded
			var defaultThresholds domain.WarningThresholds
			ui.PrintCertInfo(cert, defaultThresholds.GetCriticalDays(), defaultThresholds.GetWarningDays())
		} else {
			thresholds := caCfg.GetWarningThresholds()
			ui.PrintCertInfo(cert, thresholds.GetCriticalDays(), thresholds.GetWarningDays())
		}
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
		ui.Action("Importing existing CA certificate and private key from %s, %s", importCertPath, importKeyPath)
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
		ui.Action("Re-encrypting all private keys with updated encryption parameters")
		app := getApp(cmd)
		force, _ := cmd.Flags().GetBool("force")
		rollback, _ := cmd.Flags().GetBool("rollback")
		err := app.ReencryptKeys(cmd.Context(), force, rollback)
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

	caCreateCmd.Flags().Bool("force", false, "Skip round-trip validation")
	caRekeyCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	caReencryptCmd.Flags().Bool("force", false, "Skip round-trip validation")
	caReencryptCmd.Flags().Bool("rollback", false, "Automatically rollback from .bak files on failure")

	caInfoCmd.Flags().Bool("openssl", false, "Use openssl to display certificate information")

	caCmd.AddCommand(caCreateCmd)
	caCmd.AddCommand(caRenewCmd)
	caCmd.AddCommand(caRekeyCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caImportCmd)
	caCmd.AddCommand(caReencryptCmd)
}
