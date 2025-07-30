//go:build e2e && !windows

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const promptTimeout = 5 * time.Second

// ptyTestEnv provides PTY-based interactive testing for Unix systems
type ptyTestEnv struct {
	*testEnv
	ptmx   *os.File
	cmd    *exec.Cmd
	reader *bufio.Reader
}

// newPtyTestEnv creates a new Unix PTY-based test environment
func newPtyTestEnv(t *testing.T) *ptyTestEnv {
	return &ptyTestEnv{
		testEnv: newTestEnv(t),
	}
}

// startInteractiveCommand starts a command with PTY support on Unix
func (e *ptyTestEnv) startInteractiveCommand(args ...string) error {
	e.t.Helper()

	cmd := exec.Command(reactorCABin, args...)
	cmd.Dir = e.root
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "REACTOR_CA_ROOT="+e.root)
	// IMPORTANT: Do NOT set REACTOR_CA_PASSWORD - we want interactive prompts
	// Enable coverage collection for instrumented binary
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start PTY command: %w", err)
	}

	e.cmd = cmd
	e.ptmx = ptmx
	e.reader = bufio.NewReader(ptmx)

	return nil
}

// waitForPrompt waits for a specific prompt text to appear and returns the full output
func (e *ptyTestEnv) waitForPrompt(expectedPrompt string) (string, error) {
	e.t.Helper()

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		var output strings.Builder
		buffer := make([]byte, 1024)

		for {
			n, err := e.ptmx.Read(buffer)
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

// sendPassword sends a password to the PTY and presses enter
func (e *ptyTestEnv) sendPassword(password string) error {
	e.t.Helper()
	_, err := e.ptmx.Write([]byte(password + "\n"))
	return err
}

// cleanup waits for command completion and then closes the PTY
func (e *ptyTestEnv) cleanup() error {
	var cmdErr error
	if e.cmd != nil {
		cmdErr = e.cmd.Wait()
	}
	if e.ptmx != nil {
		e.ptmx.Close()
	}
	return cmdErr
}
