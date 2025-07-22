package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"reactor.dev/reactor-ca/cmd/reactor-ca/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		// Use color for better visibility, and a clear "Error:" prefix.
		fmt.Fprintln(os.Stderr, color.RedString("Error: %v", err))
		os.Exit(1)
	}
}
