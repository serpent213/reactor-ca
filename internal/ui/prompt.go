package ui

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompt implements the domain.UserInteraction interface.
type Prompt struct{}

// NewPrompt creates a new user interaction prompt handler.
func NewPrompt() *Prompt {
	return &Prompt{}
}

// Confirm prompts the user for a yes/no answer.
func (p *Prompt) Confirm(prompt string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("cannot prompt for confirmation in non-interactive environment: %s", prompt)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read user input: %w", err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			return true, nil
		}
		if response == "n" || response == "no" || response == "" {
			return false, nil
		}
	}
}

// PromptPassword prompts for a password without echo.
func (p *Prompt) PromptPassword(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("cannot prompt for password in non-interactive environment: %s", prompt)
	}

	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return pw, nil
}

// PromptPasswordWithConfirmation prompts for a password with confirmation.
func (p *Prompt) PromptPasswordWithConfirmation(prompt string, minLength int) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("cannot prompt for password in non-interactive environment: %s", prompt)
	}

	for {
		pw1, err := p.PromptPassword(prompt)
		if err != nil {
			return nil, err
		}

		if len(pw1) < minLength {
			fmt.Printf("Password must be at least %d characters long. Please try again.\n", minLength)
			continue
		}

		pw2, err := p.PromptPassword("Confirm Password: ")
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(pw1, pw2) {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}

		return pw1, nil
	}
}
