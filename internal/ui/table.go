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
	// Configure colors: green headers, cyan/magenta/grey cells, yellow footer
	colorCfg := renderer.ColorizedConfig{
		Header: renderer.Tint{
			FG: renderer.Colors{color.FgGreen, color.Bold},
		},
		Column: renderer.Tint{
			FG: renderer.Colors{color.FgCyan},
			Columns: []renderer.Tint{
				{FG: renderer.Colors{color.FgMagenta}}, // Host ID
				{},                                     // Key Algo
				{},                                     // Hash Algo
				{},                                     // Expires
				{FG: renderer.Colors{color.Reset}},     // Remaining
			},
		},
		Footer: renderer.Tint{
			FG: renderer.Colors{color.FgYellow, color.Bold},
			Columns: []renderer.Tint{
				{},                                      // Host ID
				{},                                      // Key Algo
				{},                                      // Hash Algo
				{},                                      // Expires
				{FG: renderer.Colors{color.FgHiYellow}}, // Remaining
			},
		},
		Border:    renderer.Tint{FG: renderer.Colors{color.FgBlue}},
		Separator: renderer.Tint{FG: renderer.Colors{color.FgBlue}},
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
