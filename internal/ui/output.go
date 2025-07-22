package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Color functions for consistent styling
var (
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// Success prints a success message with green ✓ symbol
func Success(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", green("✓"), formatted)
}

// Error prints an error message with red ✗ symbol
func Error(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", red("✗"), formatted)
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

// PrintTableHeader prints a styled table header with border
func PrintTableHeader(columns ...string) {
	header := strings.Join(columns, " | ")
	fmt.Printf("%s\n", bold(cyan(header)))
	fmt.Println(cyan(strings.Repeat("─", len(header))))
}

// FormatCertStatus returns a formatted certificate status with appropriate symbol and color
func FormatCertStatus(daysRemaining int64) string {
	if daysRemaining < 0 {
		return red("✗") + " EXPIRED"
	} else if daysRemaining < 7 {
		return red("✗") + fmt.Sprintf(" %d days", daysRemaining)
	} else if daysRemaining < 30 {
		return yellow("!") + fmt.Sprintf(" %d days", daysRemaining)
	} else {
		return green("✓") + fmt.Sprintf(" %d days", daysRemaining)
	}
}
