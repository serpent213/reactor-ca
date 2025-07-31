//go:build integration

package integration

// MockLogger provides a no-op logger for integration testing
type MockLogger struct{}

func (m *MockLogger) Info(msg string, args ...interface{})    {}
func (m *MockLogger) Error(msg string, args ...interface{})   {}
func (m *MockLogger) Warning(msg string, args ...interface{}) {}
func (m *MockLogger) Log(msg string)                          {}

// mockUserInteraction for testing user confirmation prompts
type mockUserInteraction struct {
	confirmResponse bool
}

func (m *mockUserInteraction) Confirm(prompt string) (bool, error) {
	return m.confirmResponse, nil
}
