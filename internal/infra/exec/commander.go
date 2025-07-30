package exec

// Commander implements the domain.Commander interface.
type Commander struct{}

// NewCommander creates a new Commander.
func NewCommander() *Commander {
	return &Commander{}
}
