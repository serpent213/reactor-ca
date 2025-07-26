package crypto

import (
	"reactor.de/reactor-ca/internal/domain"
)

// ServiceFactory implements domain.CryptoServiceFactory.
type ServiceFactory struct{}

// NewServiceFactory creates a new crypto service factory.
func NewServiceFactory() *ServiceFactory {
	return &ServiceFactory{}
}

// CreateCryptoService creates a crypto service with the given identity provider.
// The service is automatically wrapped with caching to avoid repeated decryption operations.
func (f *ServiceFactory) CreateCryptoService(identityProvider domain.IdentityProvider) domain.CryptoService {
	underlying := NewAgeService(identityProvider)
	return NewCachedCryptoService(underlying)
}
