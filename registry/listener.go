package registry

import (
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
)

// NewListener is a factory function that creates a new listener.Listener
// from the given options.
type NewListener func(opts ...listener.Option) listener.Listener

// listenerRegistry stores listener factory functions. Duplicate registrations
// are treated as fatal errors (logger.Default().Fatal).
type listenerRegistry struct {
	registry[NewListener]
}

// Register stores a listener factory under the given name. Calls Fatal on
// duplicate registration since listener names must be unique at init time.
func (r *listenerRegistry) Register(name string, v NewListener) error {
	if err := r.registry.Register(name, v); err != nil {
		logger.Default().Fatal(err)
	}
	return nil
}
