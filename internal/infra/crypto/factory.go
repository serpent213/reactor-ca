package crypto

import (
	"reactor.de/reactor-ca/internal/domain"
)

// ServiceFactory implements domain.CryptoServiceFactory.
type ServiceFactory struct {
	clock domain.Clock
}

// NewServiceFactory creates a new crypto service factory.
func NewServiceFactory(clock domain.Clock) *ServiceFactory {
	return &ServiceFactory{
		clock: clock,
	}
}

// CreateCryptoService creates a crypto service with the given identity provider.
// The service is automatically wrapped with caching to avoid repeated decryption operations.
func (f *ServiceFactory) CreateCryptoService(identityProvider domain.IdentityProvider) domain.CryptoService {
	underlying := NewAgeService(identityProvider, f.clock)
	return NewCachedCryptoService(underlying)
}
