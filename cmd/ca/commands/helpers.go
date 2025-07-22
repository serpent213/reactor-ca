package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/serpent213/reactor-ca/internal/app"
	"github.com/serpent213/reactor-ca/internal/ui"
	"github.com/spf13/cobra"
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
			fmt.Println("No hosts found in configuration.")
			return nil
		}
		fmt.Printf(pluralActionMsg+"\n", len(hostIDs))
	} else {
		hostIDs = append(hostIDs, args[0])
	}

	var hasErrors bool
	for _, id := range hostIDs {
		// Only print the singular action message if we are not in "all" mode,
		// as the plural message has already been printed.
		if !isAll {
			fmt.Printf(singularActionMsg+"\n", id)
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
