package main

import (
	"os"
	"regexp"
	"strings"

	"reactor.de/reactor-ca/cmd/ca/commands"
	"reactor.de/reactor-ca/internal/infra/security"
	"reactor.de/reactor-ca/internal/ui"
)

var version = "dev"

func main() {
	// Disable core dumps for security - prevents exposure of sensitive cryptographic material
	if err := security.DisableCoreDumps(); err != nil {
		// Don't fail the application if we can't disable core dumps, just warn
		ui.Warning("Failed to disable core dumps: %v", err)
	}

	if err := commands.Execute(version); err != nil {
		errorMsg := strings.ToUpper(err.Error()[:1]) + err.Error()[1:]
		errorMsg = strings.ReplaceAll(errorMsg, "\n", "\n  ")

		// Remove schema references from error messages
		schemaRefRe := regexp.MustCompile(` with 'schema://\w+#'`)
		errorMsg = schemaRefRe.ReplaceAllString(errorMsg, "")

		ui.Error("%s", errorMsg)
		os.Exit(1)
	}
}
