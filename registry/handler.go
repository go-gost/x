package registry

import (
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
)

// NewHandler is a factory function that creates a new handler.Handler
// from the given options.
type NewHandler func(opts ...handler.Option) handler.Handler

// handlerRegistry stores handler factory functions. Duplicate registrations
// are treated as fatal errors (logger.Default().Fatal).
type handlerRegistry struct {
	registry[NewHandler]
}

// Register stores a handler factory under the given name. Calls Fatal on
// duplicate registration since handler names must be unique at init time.
func (r *handlerRegistry) Register(name string, v NewHandler) error {
	if err := r.registry.Register(name, v); err != nil {
		logger.Default().Fatal(err)
	}
	return nil
}
