package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"reactor.de/reactor-ca/cmd/ca/commands"
)

var version = "dev"

func main() {
	if err := commands.Execute(version); err != nil {
		// Use color for better visibility, and a clear "Error:" prefix.
		fmt.Fprintln(os.Stderr, color.RedString("Error: %v", err))
		os.Exit(1)
	}
}
