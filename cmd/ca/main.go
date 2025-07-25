package main

import (
	"os"
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
		ui.Error("%s", strings.ToUpper(err.Error()[:1])+err.Error()[1:])
		os.Exit(1)
	}
}
