//go:build integration

package integration

// MockLogger provides a no-op logger for integration testing
type MockLogger struct{}

func (m *MockLogger) Info(msg string, args ...interface{})  {}
func (m *MockLogger) Error(msg string, args ...interface{}) {}
func (m *MockLogger) Log(msg string)                        {}
