//go:build e2e || integration

package clock

import (
	"os"
	"time"
)

func now() time.Time {
	if fakeTime := os.Getenv("REACTOR_CA_FAKE_TIME"); fakeTime != "" {
		t, err := time.Parse(time.RFC3339, fakeTime)
		if err != nil {
			panic("failed to parse REACTOR_CA_FAKE_TIME: " + err.Error())
		}
		return t
	}
	return time.Now()
}
