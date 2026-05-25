package registry

import (
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
)

// NewDialer is a factory function that creates a new dialer.Dialer
// from the given options.
type NewDialer func(opts ...dialer.Option) dialer.Dialer

// dialerRegistry stores dialer factory functions. Duplicate registrations
// are treated as fatal errors (logger.Default().Fatal).
type dialerRegistry struct {
	registry[NewDialer]
}

// Register stores a dialer factory under the given name. Calls Fatal on
// duplicate registration since dialer names must be unique at init time.
func (r *dialerRegistry) Register(name string, v NewDialer) error {
	if err := r.registry.Register(name, v); err != nil {
		logger.Default().Fatal(err)
	}
	return nil
}
