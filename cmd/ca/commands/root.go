package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"reactor.de/reactor-ca/internal/app"
	"reactor.de/reactor-ca/internal/infra/config"
	"reactor.de/reactor-ca/internal/infra/crypto"
	"reactor.de/reactor-ca/internal/infra/exec"
	"reactor.de/reactor-ca/internal/infra/identity"
	"reactor.de/reactor-ca/internal/infra/logging"
	"reactor.de/reactor-ca/internal/infra/password"
	"reactor.de/reactor-ca/internal/infra/store"
	"reactor.de/reactor-ca/internal/ui"
)

// AppContext holds all the dependencies for the application.
// It is attached to the command's context for access in RunE functions.
type AppContext struct {
	App *app.Application
}

var appContextKey = &struct{}{}

var rootCmd = &cobra.Command{
	Use:   "ca",
	Short: "ReactorCA is a tool for managing a private PKI.",
	Long: ui.GetColoredLogo() + `
ReactorCA provides a secure, reliable, and user-friendly Command-Line
Interface (CLI) for managing a private Public Key Infrastructure (PKI)
suitable for homelab and small-to-medium business environments.`,
	SilenceUsage:  true,
	SilenceErrors: true,
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
		passwordProvider := password.NewProvider()
		userInteraction := ui.NewPrompt()
		commander := exec.NewCommander()

		// Load configuration to determine encryption method
		cfg, err := configLoader.LoadCA()
		if err != nil {
			return fmt.Errorf("failed to load CA configuration: %w", err)
		}

		// Create factories
		identityProviderFactory := identity.NewFactory()
		cryptoServiceFactory := crypto.NewServiceFactory()
		validationService := crypto.NewValidationService()

		// Create identity provider based on config
		identityProvider, err := identityProviderFactory.CreateIdentityProvider(cfg, passwordProvider)
		if err != nil {
			return fmt.Errorf("failed to create identity provider: %w", err)
		}

		// Create age-based crypto service
		cryptoSvc := crypto.NewAgeService(identityProvider)

		application := app.NewApplication(
			rootPath,
			logger,
			configLoader,
			fileStore,
			cryptoSvc,
			passwordProvider,
			userInteraction,
			commander,
			identityProvider,
			identityProviderFactory,
			cryptoServiceFactory,
			validationService,
		)

		ctx := context.WithValue(cmd.Context(), appContextKey, &AppContext{App: application})
		cmd.SetContext(ctx)

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) error {
	rootCmd.Version = version
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
