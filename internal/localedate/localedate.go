// Package localedate provides simple, lightweight internationalization
// for date and time formatting.
package localedate

import (
	"golang.org/x/text/language"
	"os"
	"strings"
	"time"
)

// Constants for selecting date/datetime format types.
const (
	FormatShort = "short" // Represents a compact format, e.g., 12.08.2025
	FormatLong  = "long"  // Represents a more descriptive format, e.g., Tuesday, 8. August 2025
)

// LocaleFormats defines the various date and time format strings for a single locale.
// Note: Go's time.Format does not translate month/day names. For simplicity,
// the "long" formats will produce English names (e.g., "Monday", "August").
// This is a pragmatic choice to keep the package dependency-free.
type LocaleFormats struct {
	DateShort     string // e.g., 01/02/2006
	DateLong      string // e.g., Monday, January 2, 2006
	Time          string // e.g., 15:04:05
	DateTimeShort string // e.g., 01/02/2006 15:04
	DateTimeLong  string // e.g., Monday, January 2, 2006 15:04:05
}

// formats holds the predefined formatting rules for supported locales.
var formats = map[string]LocaleFormats{
	"en-US": { // United States
		DateShort:     "1/2/2006",
		DateLong:      "Monday, January 2, 2006",
		Time:          "3:04:05 PM",
		DateTimeShort: "1/2/2006, 3:04 PM",
		DateTimeLong:  "Monday, January 2, 2006, 3:04:05 PM MST",
	},
	"de-DE": { // Germany
		DateShort:     "02.01.2006",
		DateLong:      "Monday, 2. January 2006",
		Time:          "15:04:05",
		DateTimeShort: "02.01.2006 15:04",
		DateTimeLong:  "Monday, 2. January 2006 15:04:05 MST",
	},
	"en-GB": { // United Kingdom
		DateShort:     "02/01/2006",
		DateLong:      "Monday, 2 January 2006",
		Time:          "15:04:05",
		DateTimeShort: "02/01/2006, 15:04",
		DateTimeLong:  "Monday, 2 January 2006, 15:04:05 MST",
	},
	"fr-FR": { // France
		DateShort:     "02/01/2006",
		DateLong:      "Monday 2 January 2006",
		Time:          "15:04:05",
		DateTimeShort: "02/01/2006 15:04",
		DateTimeLong:  "Monday 2 January 2006 15:04:05 MST",
	},
	"nl-NL": { // Netherlands
		DateShort:     "02-01-2006",
		DateLong:      "Monday 2 January 2006",
		Time:          "15:04:05",
		DateTimeShort: "02-01-2006 15:04",
		DateTimeLong:  "Monday 2 January 2006 15:04:05 MST",
	},
	"sv-SE": { // Sweden (often uses ISO 8601)
		DateShort:     "2006-01-02",
		DateLong:      "Monday 2 January 2006",
		Time:          "15:04:05",
		DateTimeShort: "2006-01-02 15:04",
		DateTimeLong:  "2006-01-02 15:04:05 MST",
	},
	"en-CA": { // Canada (English)
		DateShort:     "2006-01-02",
		DateLong:      "Monday, January 2, 2006",
		Time:          "3:04:05 PM",
		DateTimeShort: "2006-01-02, 3:04 PM",
		DateTimeLong:  "Monday, January 2, 2006, 3:04:05 PM MST",
	},
	"fr-CA": { // Canada (French)
		DateShort:     "2006-01-02",
		DateLong:      "Le Monday 2 January 2006", // "Le" shows intent, but name is still English
		Time:          "15:04:05",
		DateTimeShort: "2006-01-02 15:04",
		DateTimeLong:  "Le Monday 2 January 2006 15:04:05 MST",
	},
}

// getFormats is a helper function to retrieve the format struct for a given locale,
// falling back to language-based matching, then en-GB if not found.
func getFormats(locale string) LocaleFormats {
	// Try exact match first
	if f, ok := formats[locale]; ok {
		return f
	}

	// Try language-based fallback (e.g., de-AT -> de-DE)
	if parts := strings.Split(locale, "-"); len(parts) >= 2 {
		lang := parts[0]
		for key := range formats {
			if strings.HasPrefix(key, lang+"-") {
				return formats[key]
			}
		}
	}

	return formats["en-GB"]
}

// GetUserLocaleTag discovers the user's locale and returns it as a language.Tag.
// If no locale can be determined, it returns language.BritishEnglish.
//
// This function checks environment variables in standard precedence order:
// LC_ALL overrides all, LC_MESSAGES for interface text, LANGUAGE for GNU systems, LANG as fallback.
func GetUserLocaleTag() language.Tag {
	for _, envVar := range []string{"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"} {
		if localeStr := os.Getenv(envVar); localeStr != "" {
			// Extract the core part (e.g., "de_DE" from "de_DE.UTF-8")
			base := strings.Split(localeStr, ".")[0]
			// Standardize to use hyphen instead of underscore
			standardized := strings.ReplaceAll(base, "_", "-")

			if tag, err := language.Parse(standardized); err == nil {
				return tag
			}
		}
	}
	return language.BritishEnglish
}

// FormatDate formats the date part of a time.Time object in the local timezone.
// formatType can be FormatShort or FormatLong.
func FormatDate(locale string, t time.Time, formatType string) string {
	f := getFormats(locale)
	layout := f.DateShort
	if formatType == FormatLong {
		layout = f.DateLong
	}
	return t.Local().Format(layout)
}

// FormatTime formats the time part of a time.Time object in the local timezone.
func FormatTime(locale string, t time.Time) string {
	f := getFormats(locale)
	return t.Local().Format(f.Time)
}

// FormatDateTime formats both the date and time parts of a time.Time object in the local timezone.
// formatType can be FormatShort or FormatLong.
func FormatDateTime(locale string, t time.Time, formatType string) string {
	f := getFormats(locale)
	layout := f.DateTimeShort
	if formatType == FormatLong {
		layout = f.DateTimeLong
	}
	return t.Local().Format(layout)
}
