package ui

import (
	"os"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// NewHostsTable creates a new table with consistent colorized formatting for the application
func NewHostsTable() *tablewriter.Table {
	// Configure colors: green headers, cyan/magenta rows, yellow footer
	colorCfg := renderer.ColorizedConfig{
		Header: renderer.Tint{
			FG: renderer.Colors{color.FgGreen, color.Bold}, // Green bold headers
		},
		Column: renderer.Tint{
			FG: renderer.Colors{color.FgCyan}, // Default cyan for rows
			Columns: []renderer.Tint{
				{FG: renderer.Colors{color.FgMagenta}}, // Magenta for column 0
				{},                                     // Inherit default (cyan)
				{},                                     // Inherit default (cyan)
				{},                                     // Inherit default (cyan)
				{},                                     // Inherit default (cyan)
				{},                                     // Colored individually per table
			},
		},
		Footer: renderer.Tint{
			FG: renderer.Colors{color.FgYellow, color.Bold}, // Yellow bold footer
			Columns: []renderer.Tint{
				{},                                      // Inherit default
				{},                                      // Inherit default
				{},                                      // Inherit default
				{},                                      // Inherit default
				{FG: renderer.Colors{color.FgHiYellow}}, // High-intensity yellow for totals column
				{},                                      // Inherit default
			},
		},
		Border:    renderer.Tint{FG: renderer.Colors{color.FgBlue}}, // Dark blue borders
		Separator: renderer.Tint{FG: renderer.Colors{color.FgBlue}}, // Dark blue separators
	}

	borders := tw.Border{
		Left:   tw.Off,
		Right:  tw.Off,
		Top:    tw.Off,
		Bottom: tw.Off,
	}

	// Custom symbols for horizontal-only lines with no top/bottom borders
	symbols := tw.NewSymbolCustom("HorizontalOnly").
		WithRow("─").
		WithCenter("─").
		WithColumn(" ")

	return tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewColorized(colorCfg)),
		tablewriter.WithRendition(tw.Rendition{Borders: borders, Symbols: symbols}),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Alignment:  tw.CellAlignment{Global: tw.AlignLeft}, // Left-align headers
				Formatting: tw.CellFormatting{AutoFormat: tw.Off},  // Disable auto-formatting
			},
			Row: tw.CellConfig{
				Formatting:   tw.CellFormatting{AutoWrap: tw.WrapNormal}, // Wrap long content
				Alignment:    tw.CellAlignment{Global: tw.AlignLeft},     // Left-align rows
				ColMaxWidths: tw.CellWidth{Global: 25},
			},
			Footer: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignRight},
			},
		}),
	)
}
