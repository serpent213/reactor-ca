package main

import (
	"fmt"
	"os"

	"reactor.dev/reactor-ca/cmd/reactor-ca/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
