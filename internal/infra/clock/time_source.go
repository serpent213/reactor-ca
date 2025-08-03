//go:build !e2e && !integration

package clock

import "time"

func now() time.Time {
	return time.Now()
}
