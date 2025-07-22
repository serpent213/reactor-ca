package commands

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/serpent213/reactor-ca/internal/domain"
	"github.com/serpent213/reactor-ca/internal/ui"
	"github.com/spf13/cobra"
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
		ui.Success("CA imported successfully")
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
		ui.Success("Master password changed successfully for all keys")
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
