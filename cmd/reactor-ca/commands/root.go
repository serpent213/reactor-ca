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

		rootPath, err := cmd.Flags().GetString("root")
		if err != nil {
			return err
		}
		if rootPath == "" {
			rootPath = os.Getenv("REACTOR_CA_ROOT")
		}
		if rootPath == "" {
			rootPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("could not determine current directory: %w", err)
			}
		}
		rootPath, err = filepath.Abs(rootPath)
		if err != nil {
			return fmt.Errorf("could not get absolute path for root: %w", err)
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
