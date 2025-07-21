package exec

import "os/exec"

// Commander implements the domain.Commander interface using os/exec.
type Commander struct{}

// NewCommander creates a new Commander.
func NewCommander() *Commander {
	return &Commander{}
}

// Execute runs an external command and returns its combined output.
func (c *Commander) Execute(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}
