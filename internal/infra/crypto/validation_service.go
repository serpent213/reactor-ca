package crypto

import (
	"reactor.de/reactor-ca/internal/domain"
)

// ValidationService implements domain.ValidationService.
type ValidationService struct{}

// NewValidationService creates a new validation service.
func NewValidationService() *ValidationService {
	return &ValidationService{}
}

// ValidateProviderRoundTrip performs a test encrypt/decrypt to ensure the provider works.
func (v *ValidationService) ValidateProviderRoundTrip(provider domain.IdentityProvider) error {
	return ValidateProviderRoundTrip(provider)
}
