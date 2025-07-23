package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"filippo.io/age/plugin"
	"golang.org/x/term"
)

// NewAgePluginUI creates a ClientUI for age plugin interaction with proper CLI handling.
func NewAgePluginUI() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			Info("[%s] %s", name, message)
			return nil
		},
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			fmt.Printf("%s [%s] %s: ", cyan("→"), name, prompt)

			if secret {
				// Use terminal package for secure password input
				passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return "", fmt.Errorf("failed to read secret input: %w", err)
				}
				fmt.Println() // Add newline after password input
				return string(passwordBytes), nil
			}

			// Regular input with echo
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return "", fmt.Errorf("failed to read input: %w", err)
				}
				return "", fmt.Errorf("no input provided")
			}

			return strings.TrimSpace(scanner.Text()), nil
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			choices := yes
			if no != "" {
				choices = fmt.Sprintf("%s/%s", yes, no)
			}

			fmt.Printf("%s [%s] %s [%s]: ", cyan("?"), name, prompt, choices)

			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return false, fmt.Errorf("failed to read response: %w", err)
				}
				return false, fmt.Errorf("no response provided")
			}

			response := strings.TrimSpace(strings.ToLower(scanner.Text()))
			yesLower := strings.ToLower(yes)

			// Accept full word or first letter
			return response == yesLower || (len(response) == 1 && len(yesLower) > 0 && response[0] == yesLower[0]), nil
		},
		WaitTimer: func(name string) {
			Action("[%s] Waiting for plugin response (touch hardware token if required)...", name)
		},
	}
}
