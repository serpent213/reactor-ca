//go:build windows

package exec

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"

	cpty "github.com/qsocket/conpty-go"
	"golang.org/x/term"
)

// ExecuteInteractive runs a command with ConPTY support on Windows.
func (c *Commander) ExecuteInteractive(name string, args ...string) error {
	// Check if we're running in a terminal environment
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Fallback to non-interactive execution for CI/non-TTY environments
		cmd := exec.Command(name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Build command line for ConPTY
	cmdLine := append([]string{name}, args...)
	cmdStr := strings.Join(cmdLine, " ")

	// Start ConPTY
	conpty, err := cpty.Start(cmdStr)
	if err != nil {
		return err
	}
	defer conpty.Close()

	// Put terminal in raw mode for proper PTY interaction
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Forward data between ConPTY and real terminal
	go io.Copy(conpty, os.Stdin)  // user input → child process
	go io.Copy(os.Stdout, conpty) // child output → user terminal

	// Wait for command completion
	_, err = conpty.Wait(context.Background())
	return err
}
