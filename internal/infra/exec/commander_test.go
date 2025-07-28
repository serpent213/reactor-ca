//go:build !integration && !e2e

package exec

import (
	"runtime"
	"strings"
	"testing"
)

func TestCommander_Execute(t *testing.T) {
	commander := NewCommander()

	tests := []struct {
		name     string
		command  string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "echo command",
			command:  "echo",
			args:     []string{"hello world"},
			wantErr:  false,
			contains: "hello world",
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
			name     string
			command  string
			args     []string
			wantErr  bool
			contains string
		}{
			name:     "pwd command",
			command:  "pwd",
			args:     []string{},
			wantErr:  false,
			contains: "/", // should contain a path separator
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := commander.Execute(tt.command, tt.args...)

			if tt.wantErr {
				if err == nil {
					t.Error("Execute() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Execute() unexpected error: %v", err)
				return
			}

			outputStr := string(output)
			if tt.contains != "" && !strings.Contains(outputStr, tt.contains) {
				t.Errorf("Execute() output %q does not contain %q", outputStr, tt.contains)
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
