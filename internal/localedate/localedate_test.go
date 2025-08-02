package localedate

import (
	"os"
	"testing"
	"time"
)

func TestGetUserLocaleTag(t *testing.T) {
	// Save original environment
	originalEnvs := map[string]string{
		"LC_ALL":      os.Getenv("LC_ALL"),
		"LC_MESSAGES": os.Getenv("LC_MESSAGES"),
		"LANGUAGE":    os.Getenv("LANGUAGE"),
		"LANG":        os.Getenv("LANG"),
	}

	// Clean up after test
	defer func() {
		for key, value := range originalEnvs {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	tests := []struct {
		name     string
		envVars  map[string]string
		expected string
	}{
		{
			name: "LC_ALL takes precedence",
			envVars: map[string]string{
				"LC_ALL":      "de_DE.UTF-8",
				"LC_MESSAGES": "fr_FR",
				"LANG":        "en_US",
			},
			expected: "de-DE",
		},
		{
			name: "LC_MESSAGES when LC_ALL empty",
			envVars: map[string]string{
				"LC_ALL":      "",
				"LC_MESSAGES": "fr_FR.UTF-8",
				"LANG":        "en_US",
			},
			expected: "fr-FR",
		},
		{
			name: "LANGUAGE fallback",
			envVars: map[string]string{
				"LC_ALL":      "",
				"LC_MESSAGES": "",
				"LANGUAGE":    "sv_SE",
				"LANG":        "en_US",
			},
			expected: "sv-SE",
		},
		{
			name: "LANG fallback",
			envVars: map[string]string{
				"LC_ALL":      "",
				"LC_MESSAGES": "",
				"LANGUAGE":    "",
				"LANG":        "en_CA.UTF-8",
			},
			expected: "en-CA",
		},
		{
			name: "Default when all empty",
			envVars: map[string]string{
				"LC_ALL":      "",
				"LC_MESSAGES": "",
				"LANGUAGE":    "",
				"LANG":        "",
			},
			expected: "en-GB",
		},
		{
			name: "Invalid locale falls back to default",
			envVars: map[string]string{
				"LANG": "invalid_locale",
			},
			expected: "en-GB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all environment variables
			for key := range originalEnvs {
				os.Unsetenv(key)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				if value != "" {
					os.Setenv(key, value)
				}
			}

			result := GetUserLocaleTag().String()
			if result != tt.expected {
				t.Errorf("GetUserLocaleTag().String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFormatDate(t *testing.T) {
	testTime := time.Date(2025, 8, 2, 15, 30, 45, 0, time.UTC)

	tests := []struct {
		name       string
		locale     string
		formatType string
		expected   string
	}{
		{
			name:       "US short format",
			locale:     "en-US",
			formatType: FormatShort,
			expected:   "8/2/2025",
		},
		{
			name:       "US long format",
			locale:     "en-US",
			formatType: FormatLong,
			expected:   "Saturday, August 2, 2025",
		},
		{
			name:       "German short format",
			locale:     "de-DE",
			formatType: FormatShort,
			expected:   "02.08.2025",
		},
		{
			name:       "German long format",
			locale:     "de-DE",
			formatType: FormatLong,
			expected:   "Saturday, 2. August 2025",
		},
		{
			name:       "Swedish ISO format",
			locale:     "sv-SE",
			formatType: FormatShort,
			expected:   "2025-08-02",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDate(tt.locale, testTime, tt.formatType)
			if result != tt.expected {
				t.Errorf("FormatDate() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatTime(t *testing.T) {
	// Set timezone to Moscow for consistent test results
	moscow, _ := time.LoadLocation("Europe/Moscow")
	originalLocal := time.Local
	time.Local = moscow
	defer func() {
		time.Local = originalLocal
	}()

	testTime := time.Date(2025, 8, 2, 15, 30, 45, 0, moscow)

	tests := []struct {
		name     string
		locale   string
		expected string
	}{
		{
			name:     "US 12-hour format",
			locale:   "en-US",
			expected: "3:30:45 PM",
		},
		{
			name:     "German 24-hour format",
			locale:   "de-DE",
			expected: "15:30:45",
		},
		{
			name:     "British 24-hour format",
			locale:   "en-GB",
			expected: "15:30:45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTime(tt.locale, testTime)
			if result != tt.expected {
				t.Errorf("FormatTime() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatDateTime(t *testing.T) {
	// Set timezone to Moscow for consistent test results
	moscow, _ := time.LoadLocation("Europe/Moscow")
	originalLocal := time.Local
	time.Local = moscow
	defer func() {
		time.Local = originalLocal
	}()

	testTime := time.Date(2025, 8, 2, 15, 30, 45, 0, moscow)

	tests := []struct {
		name       string
		locale     string
		formatType string
		expected   string
	}{
		{
			name:       "US short datetime",
			locale:     "en-US",
			formatType: FormatShort,
			expected:   "8/2/2025, 3:30 PM",
		},
		{
			name:       "US long datetime",
			locale:     "en-US",
			formatType: FormatLong,
			expected:   "Saturday, August 2, 2025, 3:30:45 PM MSK",
		},
		{
			name:       "German short datetime",
			locale:     "de-DE",
			formatType: FormatShort,
			expected:   "02.08.2025 15:30",
		},
		{
			name:       "Swedish ISO datetime",
			locale:     "sv-SE",
			formatType: FormatShort,
			expected:   "2025-08-02 15:30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDateTime(tt.locale, testTime, tt.formatType)
			if result != tt.expected {
				t.Errorf("FormatDateTime() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetFormats(t *testing.T) {
	// Test known locale
	formats := getFormats("de-DE")
	if formats.DateShort != "02.01.2006" {
		t.Errorf("Expected German short date format, got %q", formats.DateShort)
	}

	// Test unknown locale falls back to British English
	formats = getFormats("xx-XX")
	expectedFallback := getFormats("en-GB")
	if formats.DateShort != expectedFallback.DateShort {
		t.Errorf("Expected fallback to British English, got %q", formats.DateShort)
	}
}
