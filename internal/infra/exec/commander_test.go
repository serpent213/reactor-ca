//go:build !integration && !e2e

package exec

import (
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestCommander_ExecuteInteractive(t *testing.T) {
	commander := NewCommander()

	tests := []struct {
		name    string
		command string
		args    []string
		wantErr bool
		skip    string
	}{
		{
			name:    "echo command in non-TTY",
			command: "echo",
			args:    []string{"hello world"},
			wantErr: false,
		},
		{
			name:    "invalid command",
			command: "nonexistent-command-12345",
			args:    []string{},
			wantErr: true,
		},
	}

	// Add platform-specific test
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name    string
			command string
			args    []string
			wantErr bool
			skip    string
		}{
			name:    "true command",
			command: "true",
			args:    []string{},
			wantErr: false,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip != "" {
				t.Skip(tt.skip)
			}

			// Since we're running in a test environment (non-TTY),
			// ExecuteInteractive should fall back to regular execution
			if term.IsTerminal(int(os.Stdin.Fd())) {
				t.Skip("Test running in TTY environment, skipping non-TTY test")
			}

			// Use a timeout to prevent hanging
			done := make(chan error, 1)
			go func() {
				done <- commander.ExecuteInteractive(tt.command, tt.args...)
			}()

			select {
			case err := <-done:
				if tt.wantErr {
					if err == nil {
						t.Error("ExecuteInteractive() expected error, got nil")
					}
					return
				}

				if err != nil {
					t.Errorf("ExecuteInteractive() unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("ExecuteInteractive() timed out - command may have hung")
			}
		})
	}
}

func TestNewCommander(t *testing.T) {
	commander := NewCommander()
	if commander == nil {
		t.Error("NewCommander() returned nil")
	}
}
