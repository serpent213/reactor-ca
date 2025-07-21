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
		appCtx := cmd.Context().Value(appContextKey).(*AppContext)
		err := appCtx.App.ValidateConfig(cmd.Context())
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
