package password

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
	"reactor.de/reactor-ca/internal/domain"
)

// Provider implements the domain.PasswordProvider interface.
type Provider struct{}

// NewProvider creates a new password provider.
func NewProvider() *Provider {
	return &Provider{}
}

// GetMasterPassword retrieves the master password from file, env, or interactive prompt.
func (p *Provider) GetMasterPassword(ctx context.Context, cfg domain.PasswordConfig) ([]byte, error) {
	// 1. From file
	if cfg.File != "" {
		if pw, err := os.ReadFile(cfg.File); err == nil {
			return bytes.TrimSpace(pw), nil
		}
	}

	// 2. From environment variable
	if cfg.EnvVar != "" {
		if pw := os.Getenv(cfg.EnvVar); pw != "" {
			return []byte(pw), nil
		}
	}

	// 3. Interactive prompt
	fmt.Print("Enter Master Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return pw, nil
}

// GetNewMasterPassword prompts the user to enter and confirm a new password.
func (p *Provider) GetNewMasterPassword(ctx context.Context, minLength int) ([]byte, error) {
	// Check if we're in a non-interactive environment and try env var fallback
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if pw := os.Getenv("REACTOR_CA_PASSWORD"); pw != "" {
			if len(pw) < minLength {
				return nil, fmt.Errorf("password from REACTOR_CA_PASSWORD is too short (minimum %d characters)", minLength)
			}
			return []byte(pw), nil
		}
		return nil, fmt.Errorf("running in non-interactive environment but no password provided via REACTOR_CA_PASSWORD environment variable")
	}

	for {
		fmt.Print("Enter New Master Password: ")
		pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("failed to read password interactively: %w", err)
		}

		if len(pw1) < minLength {
			fmt.Printf("Password must be at least %d characters long. Please try again.\n", minLength)
			continue
		}

		fmt.Print("Confirm New Master Password: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
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

// GetPasswordForImport prompts for a new password to encrypt an imported key.
func (p *Provider) GetPasswordForImport(ctx context.Context, minLength int) ([]byte, error) {
	fmt.Println("Enter a new master password to encrypt the imported private key.")
	return p.GetNewMasterPassword(ctx, minLength)
}

// Confirm prompts the user for a yes/no answer.
func (p *Provider) Confirm(prompt string) (bool, error) {
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
