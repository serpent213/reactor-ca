//go:build e2e || integration

package clock

import (
	"os"
	"time"
)

// Now returns the current time, or fake time if REACTOR_CA_FAKE_TIME is set.
// This allows deterministic time testing in e2e and integration tests.
func Now() time.Time {
	if fakeTime := os.Getenv("REACTOR_CA_FAKE_TIME"); fakeTime != "" {
		t, err := time.Parse(time.RFC3339, fakeTime)
		if err != nil {
			panic("failed to parse REACTOR_CA_FAKE_TIME: " + err.Error())
		}
		return t
	}
	return time.Now()
}
