package app

import (
	"os"
	"path/filepath"

	"reactor.de/reactor-ca/internal/domain"
)

// Application orchestrates the application's use cases.
type Application struct {
	rootPath                string
	logger                  domain.Logger
	configLoader            domain.ConfigLoader
	store                   domain.Store
	cryptoSvc               domain.CryptoService
	passwordProvider        domain.PasswordProvider
	userInteraction         domain.UserInteraction
	commander               domain.Commander
	identityProvider        domain.IdentityProvider
	identityProviderFactory domain.IdentityProviderFactory
	cryptoServiceFactory    domain.CryptoServiceFactory
	validationService       domain.ValidationService
	clock                   domain.Clock
}

// NewApplication creates a new Application instance.
func NewApplication(
	rootPath string,
	logger domain.Logger,
	configLoader domain.ConfigLoader,
	store domain.Store,
	cryptoSvc domain.CryptoService,
	passwordProvider domain.PasswordProvider,
	userInteraction domain.UserInteraction,
	commander domain.Commander,
	identityProvider domain.IdentityProvider,
	identityProviderFactory domain.IdentityProviderFactory,
	cryptoServiceFactory domain.CryptoServiceFactory,
	validationService domain.ValidationService,
	clock domain.Clock,
) *Application {
	return &Application{
		rootPath:                rootPath,
		logger:                  logger,
		configLoader:            configLoader,
		store:                   store,
		cryptoSvc:               cryptoSvc,
		passwordProvider:        passwordProvider,
		userInteraction:         userInteraction,
		commander:               commander,
		identityProvider:        identityProvider,
		identityProviderFactory: identityProviderFactory,
		cryptoServiceFactory:    cryptoServiceFactory,
		validationService:       validationService,
		clock:                   clock,
	}
}

// GetCAConfig returns the CA configuration with defaults applied.
func (a *Application) GetCAConfig() (*domain.CAConfig, error) {
	return a.configLoader.LoadCA()
}

// GetStore returns the store instance.
func (a *Application) GetStore() domain.Store {
	return a.store
}

// GetClock returns the clock instance.
func (a *Application) GetClock() domain.Clock {
	return a.clock
}

func (a *Application) writeFileWithDir(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}
