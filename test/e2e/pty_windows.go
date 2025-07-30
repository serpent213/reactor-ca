//go:build e2e && windows

package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	cpty "github.com/qsocket/conpty-go"
	"golang.org/x/term"
)

const promptTimeout = 5 * time.Second

// ptyTestEnv provides ConPTY-based interactive testing for Windows
type ptyTestEnv struct {
	*testEnv
	conpty *cpty.ConPty
	ctx    context.Context
	cancel context.CancelFunc
}

// newPtyTestEnv creates a new Windows ConPTY-based test environment
func newPtyTestEnv(t *testing.T) *ptyTestEnv {
	return &ptyTestEnv{
		testEnv: newTestEnv(t),
	}
}

// startInteractiveCommand starts a command with ConPTY support on Windows
func (e *ptyTestEnv) startInteractiveCommand(args ...string) error {
	e.t.Helper()

	// Check if we're in a non-TTY environment (CI)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("failed to start PTY command: unsupported")
	}

	// Build command line for ConPTY
	cmdLine := append([]string{reactorCABin}, args...)
	cmdStr := strings.Join(cmdLine, " ")

	// Create context for cancellation
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Start ConPTY
	conpty, err := cpty.Start(cmdStr)
	if err != nil {
		return fmt.Errorf("failed to start PTY command: %w", err)
	}

	e.conpty = conpty
	return nil
}

// waitForPrompt waits for a specific prompt text to appear
func (e *ptyTestEnv) waitForPrompt(expectedPrompt string) (string, error) {
	e.t.Helper()

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		var output strings.Builder
		buffer := make([]byte, 1024)

		for {
			select {
			case <-e.ctx.Done():
				return
			default:
				n, err := e.conpty.Read(buffer)
				if err != nil {
					if err != io.EOF {
						errCh <- err
					}
					return
				}

				if n > 0 {
					chunk := buffer[:n]
					output.Write(chunk)

					if strings.Contains(output.String(), expectedPrompt) {
						resultCh <- output.String()
						return
					}
				}
			}
		}
	}()

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return "", fmt.Errorf("read error: %w", err)
	case <-time.After(promptTimeout):
		return "", fmt.Errorf("timeout waiting for prompt '%s'", expectedPrompt)
	}
}

// sendPassword sends a password to the ConPTY
func (e *ptyTestEnv) sendPassword(password string) error {
	e.t.Helper()
	_, err := e.conpty.Write([]byte(password + "\r\n"))
	return err
}

// cleanup waits for command completion and closes the ConPTY
func (e *ptyTestEnv) cleanup() error {
	var err error
	if e.conpty != nil {
		if e.cancel != nil {
			e.cancel()
		}
		_, err = e.conpty.Wait(e.ctx)
		e.conpty.Close()
	}
	return err
}
