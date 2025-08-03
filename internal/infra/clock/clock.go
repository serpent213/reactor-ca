package clock

import (
	"time"

	"reactor.de/reactor-ca/internal/domain"
)

// Service implements the Clock interface for real time operations.
type Service struct{}

// NewService creates a new real clock service.
func NewService() domain.Clock {
	return &Service{}
}

// Now returns the current time.
func (s *Service) Now() time.Time {
	return now()
}
