package commands

import (
	"fmt"

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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.CreateCA(cmd.Context())
		if err != nil {
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.RenewCA(cmd.Context())
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
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		force, _ := cmd.Flags().GetBool("force")
		err := appCtx.App.RekeyCA(cmd.Context(), force)
		if err != nil {
			return err
		}
		fmt.Println("✅ CA re-keyed successfully.")
		return nil
	},
}

// ca info
var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display detailed information about the CA certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		info, err := appCtx.App.InfoCA(cmd.Context())
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ImportCA(cmd.Context(), importCertPath, importKeyPath)
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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ChangePassword(cmd.Context())
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
