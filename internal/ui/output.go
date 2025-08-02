package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// Color functions for consistent styling
var (
	green  = color.New(color.FgGreen).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// Success prints a success message with green ✓ symbol
func Success(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", green("✓"), formatted)
}

// Error prints an error message with red ⚠ symbol
func Error(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", red("⚠"), formatted)
}

// Warning prints a warning message with yellow ! symbol
func Warning(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", yellow("!"), formatted)
}

// Info prints an info message with cyan i symbol
func Info(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", cyan("i"), formatted)
}

// Action prints an action/progress message with cyan → symbol
func Action(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", cyan("→"), formatted)
}

// PrintBlock prints a block of pre-formatted text, such as certificate details.
// This ensures all command output goes through the UI package for consistency.
func PrintBlock(text string) {
	fmt.Println(text)
}

// PrintTableHeaderWithWidths prints a styled table header with border using specified column widths
func PrintTableHeaderWithWidths(columnWidths []int, columns ...string) {
	var formattedColumns []string
	for i, col := range columns {
		if i < len(columnWidths) {
			formattedColumns = append(formattedColumns, fmt.Sprintf("%-*s", columnWidths[i], col))
		} else {
			// Last column is variable width
			formattedColumns = append(formattedColumns, col)
		}
	}

	header := strings.Join(formattedColumns, " | ")
	fmt.Printf("%s\n", bold(cyan(header)))
	fmt.Println(cyan(strings.Repeat("─", len(header))))
}

// FormatHostStatus returns a formatted host status with appropriate symbol and color
func FormatHostStatus(status string) string {
	switch status {
	case "configured":
		return yellow("○") + " CONFIGURED"
	case "orphaned":
		return yellow("!") + " ORPHANED"
	case "key_only":
		return red("⚠") + " CERT MISSING"
	case "cert_only":
		return red("⚠") + " KEY MISSING"
	default:
		return "UNKNOWN"
	}
}

// GetColoredLogo returns the ReactorCA ASCII art logo with Reactor in cyan and CA in gray
func GetColoredLogo() string {
	gray := color.New(color.FgHiBlack).SprintFunc()

	// Split each line at the boundary between "Reactor" and "CA"
	lines := []struct{ left, right string }{
		{" ______                                    ", "______"},
		{"(_____ \\                  _               ", "/ _____)  /\\"},
		{" _____) ) ____ ____  ____| |_  ___   ____", "| /       /  \\"},
		{"(_____ ( / _  ) _  |/ ___)  _)/ _ \\ / ___) ", "|      / /\\ \\"},
		{"      | ( (/ ( ( | ( (___| |_| |_| | |   ", "| \\_____| |__| |"},
		{"      |_|\\____)_||_|\\____)\\___}___/|_|    ", "\\______)______|"},
	}

	var result strings.Builder
	for _, line := range lines {
		result.WriteString(cyan(line.left) + gray(line.right) + "\n")
	}

	return result.String()
}
