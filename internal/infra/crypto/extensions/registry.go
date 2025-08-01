package extensions

import (
	"fmt"
	"sort"
	"sync"

	"reactor.de/reactor-ca/internal/domain"
)

// Registry implements domain.ExtensionFactory with thread-safe extension registration
type Registry struct {
	mu         sync.RWMutex
	extensions map[string]func() domain.Extension
}

// NewRegistry creates a new extension registry with built-in extensions pre-registered
func NewRegistry() *Registry {
	r := &Registry{
		extensions: make(map[string]func() domain.Extension),
	}

	// Register built-in extensions
	r.registerBuiltinExtensions()

	return r
}

// CreateExtension creates an extension by name, returns nil if unknown
func (r *Registry) CreateExtension(name string) domain.Extension {
	r.mu.RLock()
	creator, exists := r.extensions[name]
	r.mu.RUnlock()

	if !exists {
		return nil
	}

	return creator()
}

// RegisterExtension registers a new extension type
func (r *Registry) RegisterExtension(name string, creator func() domain.Extension) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.extensions[name] = creator
}

// ListExtensions returns all registered extension names in sorted order
func (r *Registry) ListExtensions() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.extensions))
	for name := range r.extensions {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// IsRegistered checks if an extension name is registered
func (r *Registry) IsRegistered(name string) bool {
	r.mu.RLock()
	_, exists := r.extensions[name]
	r.mu.RUnlock()

	return exists
}

// registerBuiltinExtensions registers all built-in extension types
func (r *Registry) registerBuiltinExtensions() {
	// Basic Constraints Extension
	r.extensions["basic_constraints"] = func() domain.Extension {
		return &BasicConstraintsExtension{}
	}

	// Key Usage Extension
	r.extensions["key_usage"] = func() domain.Extension {
		return &KeyUsageExtension{}
	}

	// Extended Key Usage Extension
	r.extensions["extended_key_usage"] = func() domain.Extension {
		return &ExtendedKeyUsageExtension{}
	}

	// Subject Key Identifier Extension
	r.extensions["subject_key_identifier"] = func() domain.Extension {
		return &SubjectKeyIdentifierExtension{}
	}

	// Authority Key Identifier Extension
	r.extensions["authority_key_identifier"] = func() domain.Extension {
		return &AuthorityKeyIdentifierExtension{}
	}

	// Name Constraints Extension
	r.extensions["name_constraints"] = func() domain.Extension {
		return &NameConstraintsExtension{}
	}

	// CRL Distribution Points Extension (structured)
	r.extensions["crl_distribution_points"] = func() domain.Extension {
		return &CRLDistributionPointsExtension{}
	}
}

// parseFieldAs provides type-safe field parsing utilities for extensions
func parseFieldAs[T any](data map[string]interface{}, key string, defaultValue T) T {
	if val, exists := data[key]; exists {
		if typed, ok := val.(T); ok {
			return typed
		}
	}
	return defaultValue
}

// parseFieldAsPtr returns a pointer to the parsed value or nil if not present
func parseFieldAsPtr[T any](data map[string]interface{}, key string) *T {
	if val, exists := data[key]; exists {
		if typed, ok := val.(T); ok {
			return &typed
		}
	}
	return nil
}

// parseStringSlice parses a field as a slice of strings
func parseStringSlice(data map[string]interface{}, key string) []string {
	if val, exists := data[key]; exists {
		if slice, ok := val.([]interface{}); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

// validateRequiredField checks that a required field exists and returns an error if missing
func validateRequiredField(data map[string]interface{}, field string) error {
	if _, exists := data[field]; !exists {
		return fmt.Errorf("required field '%s' is missing", field)
	}
	return nil
}
