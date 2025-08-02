package ui

import (
	"strings"
	"testing"
	"time"
)

func TestFormatCertExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		durationHours float64
		criticalDays  int
		warningDays   int
		expectSymbol  string // First character of expected output (✗, !, ✓)
		expectText    string // Expected text portion (without ANSI codes)
	}{
		// Negative values (expired certificates)
		{
			name:          "expired by 1 hour",
			durationHours: -1,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "-1 hours",
		},
		{
			name:          "expired by 0.2 hours (12 minutes)",
			durationHours: -0.2,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "< 0 hours",
		},
		{
			name:          "expired by 25 hours",
			durationHours: -25,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "-1 d (-25 h)",
		},
		{
			name:          "expired by 8 days",
			durationHours: -8 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "-8 d (-192 h)",
		},
		{
			name:          "expired by 400 days",
			durationHours: -400 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "-400 d (-9,600 h)",
		},

		// Zero duration (expires right now)
		{
			name:          "expires exactly now",
			durationHours: 0,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "0 hours",
		},

		// Small positive values
		{
			name:          "expires in 0.3 hours",
			durationHours: 0.3,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "0 hours",
		},
		{
			name:          "expires in 1 hour",
			durationHours: 1,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "1 hour",
		},
		{
			name:          "expires in 23 hours",
			durationHours: 23,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "1 d (23 h)",
		},
		{
			name:          "expires in 24 hours",
			durationHours: 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "1 d (24 h)",
		},
		{
			name:          "expires in 25 hours",
			durationHours: 25,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "1 d (25 h)",
		},

		// Critical range tests
		{
			name:          "expires in 7 days (critical boundary)",
			durationHours: 7 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "7 days",
		},
		{
			name:          "expires in 6 days (within critical)",
			durationHours: 6 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "6 days",
		},

		// Warning range tests
		{
			name:          "expires in 8 days (warning range)",
			durationHours: 8 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "!",
			expectText:    "8 days",
		},
		{
			name:          "expires in 30 days (warning boundary)",
			durationHours: 30 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "!",
			expectText:    "30 days",
		},

		// Good range tests
		{
			name:          "expires in 31 days (good)",
			durationHours: 31 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "31 days",
		},
		{
			name:          "expires in 90 days",
			durationHours: 90 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "90 days",
		},
		{
			name:          "expires in 365 days",
			durationHours: 365 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "365 days",
		},

		// Large values (years)
		{
			name:          "expires in 400 days",
			durationHours: 400 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "400 d (1.1 y)",
		},
		{
			name:          "expires in 730 days (2 years)",
			durationHours: 730 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "730 d (2.0 y)",
		},
		{
			name:          "expires in 3650 days (10 years)",
			durationHours: 3650 * 24,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✓",
			expectText:    "3,650 d (10.0 y)",
		},

		// Edge case: Different threshold configurations
		{
			name:          "zero critical days",
			durationHours: 1,
			criticalDays:  0,
			warningDays:   7,
			expectSymbol:  "✗",
			expectText:    "1 hour",
		},
		{
			name:          "same critical and warning days",
			durationHours: 7 * 24,
			criticalDays:  7,
			warningDays:   7,
			expectSymbol:  "✗",
			expectText:    "7 days",
		},
		{
			name:          "warning less than critical (unusual config)",
			durationHours: 10 * 24,
			criticalDays:  14,
			warningDays:   7,
			expectSymbol:  "✗",
			expectText:    "10 days",
		},

		// Edge case: 48-49 hours (boundary between day formats)
		{
			name:          "expires in 48 hours",
			durationHours: 48,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "2 d (48 h)",
		},
		{
			name:          "expires in 71 hours",
			durationHours: 71,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "3 days",
		},
		{
			name:          "expires in 72 hours",
			durationHours: 72,
			criticalDays:  7,
			warningDays:   30,
			expectSymbol:  "✗",
			expectText:    "3 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate expiry time from duration
			duration := time.Duration(tt.durationHours * float64(time.Hour))
			expiryTime := now.Add(duration)

			// Call the function
			result := FormatCertExpiry(expiryTime, tt.criticalDays, tt.warningDays, true, now)

			// Check symbol (first character as rune)
			if len(result) == 0 {
				t.Fatalf("Expected non-empty result")
			}

			runes := []rune(result)
			firstChar := string(runes[0])
			if firstChar != tt.expectSymbol {
				t.Errorf("Expected symbol %q, got %q", tt.expectSymbol, firstChar)
			}

			// Check text content (skip first symbol and space)
			if len(runes) < 3 {
				t.Fatalf("Result too short: %q", result)
			}

			// Extract text after "symbol "
			textPart := strings.TrimSpace(string(runes[2:])) // Skip symbol and space
			if textPart != tt.expectText {
				t.Errorf("Expected text %q, got %q", tt.expectText, textPart)
			}
		})
	}
}

func TestFormatCertExpiryEdgeCasesRounding(t *testing.T) {
	now := time.Now()

	// Test rounding behavior with fractional hours
	tests := []struct {
		name     string
		hours    float64
		expected string
	}{
		{"11 hours stays as hours", 11, "11 hours"},
		{"12 hours stays as hours", 12, "1 d (12 h)"},
		{"13 hours rounds to 1 day", 13, "1 d (13 h)"},
		{"0.4 hours shows as 0", 0.4, "0 hours"},
		{"0.5 hours shows as 0", 0.5, "0 hours"},
		{"0.6 hours shows as 0", 0.6, "0 hours"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := time.Duration(tt.hours * float64(time.Hour))
			expiryTime := now.Add(duration)
			result := FormatCertExpiry(expiryTime, 7, 30, true, now)

			// Extract text after symbol and space (using runes for proper Unicode handling)
			runes := []rune(result)
			if len(runes) < 3 {
				t.Fatalf("Result too short: %q", result)
			}
			textPart := strings.TrimSpace(string(runes[2:]))
			if textPart != tt.expected {
				t.Errorf("For %.1f hours, expected %q, got %q", tt.hours, tt.expected, textPart)
			}
		})
	}
}

func TestFormatCertExpiry_LongFormat(t *testing.T) {
	now := time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)

	// Test one basic case with short = false to ensure longer format works
	expiryTime := now.Add(48 * time.Hour) // 2 days from now
	result := FormatCertExpiry(expiryTime, 7, 30, false, now)

	// Should contain more detailed information than short format
	if len(result) == 0 {
		t.Fatalf("Expected non-empty result")
	}

	// The long format should contain more characters than short format
	shortResult := FormatCertExpiry(expiryTime, 7, 30, true, now)
	if len(result) <= len(shortResult) {
		t.Errorf("Expected long format to be longer than short format. Long: %q, Short: %q", result, shortResult)
	}

	// The long format should contain "days" for detailed time information
	if !strings.Contains(result, "days") {
		t.Errorf("Expected long format to contain 'days', got: %q", result)
	}
}
