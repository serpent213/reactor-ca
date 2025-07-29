//go:build !windows

package exec

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// ExecuteInteractive runs a command with full PTY support for interactive deployment scripts.
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

	// Unix PTY implementation
	cmd := exec.Command(name, args...)

	// Start the command with a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	// Handle window resize signals
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			_ = pty.InheritSize(os.Stdin, ptmx) // best effort
		}
	}()
	ch <- syscall.SIGWINCH // trigger initial resize

	// Put terminal in raw mode for proper PTY interaction
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Forward data between PTY and real terminal
	go io.Copy(ptmx, os.Stdin) // user input → child process
	io.Copy(os.Stdout, ptmx)   // child output → user terminal

	// Wait for command completion
	return cmd.Wait()
}
