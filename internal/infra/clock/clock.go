//go:build !e2e && !integration

package clock

import "time"

// Now returns the current time. Is replaced in test builds to allow time faking.
func Now() time.Time {
	return time.Now()
}
