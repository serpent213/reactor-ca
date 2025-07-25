package main

import (
	"os"
	"strings"

	"reactor.de/reactor-ca/cmd/ca/commands"
	"reactor.de/reactor-ca/internal/ui"
)

var version = "dev"

func main() {
	if err := commands.Execute(version); err != nil {
		ui.Error("%s", strings.ToUpper(err.Error()[:1])+err.Error()[1:])
		os.Exit(1)
	}
}
