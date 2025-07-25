package commands

import (
	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/ui"
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
		ui.Action("Validating configuration files (ca.yaml and hosts.yaml)")
		app := getApp(cmd)
		err := app.ValidateConfig(cmd.Context())
		if err != nil {
			return err
		}
		ui.Success("Configuration files are valid")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}
