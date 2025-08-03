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

// Symbol helper functions that return colored strings
func SuccessSymbol() string {
	return green("✓")
}

func ErrorSymbol() string {
	return red("⚠")
}

func WarningSymbol() string {
	return yellow("!")
}

func InfoSymbol() string {
	return cyan("i")
}

func ActionSymbol() string {
	return cyan("→")
}

func PendingSymbol() string {
	return yellow("○")
}

// Success prints a success message with green ✓ symbol
func Success(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", SuccessSymbol(), formatted)
}

// Error prints an error message with red ⚠ symbol
func Error(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", ErrorSymbol(), formatted)
}

// Warning prints a warning message with yellow ! symbol
func Warning(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", WarningSymbol(), formatted)
}

// Info prints an info message with cyan i symbol
func Info(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", InfoSymbol(), formatted)
}

// Action prints an action/progress message with cyan → symbol
func Action(msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	fmt.Printf("%s %s\n", ActionSymbol(), formatted)
}

// GetColoredLogo returns the ReactorCA ASCII art logo with Reactor in cyan and CA in gray
func GetColoredLogo() string {
	gray := color.New(color.FgHiBlack).SprintFunc()

	// Split each line at the boundary between "Reactor" and "CA"
	lines := []struct{ left, right string }{
		{" ______                                    ", "______"},
		{"(_____ \\                  _               ", "/ _____)  /\\"},
		{" _____) ) ____ ____  ____| |_  ___   ____", "| /       /  \\"},
		{"(_____ ( / _  ) _  |/ ___)  _)/ _ \\ / ___)", " |      / /\\ \\"},
		{"      | ( (/ ( ( | ( (___| |_| |_| | |   ", "| \\_____| |__| |"},
		{"      |_|\\____)_||_|\\____)\\___}___/|_|    ", "\\______)______|"},
	}

	var result strings.Builder
	for _, line := range lines {
		result.WriteString(cyan(line.left) + gray(line.right) + "\n")
	}

	return result.String()
}
