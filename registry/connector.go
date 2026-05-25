package registry

import (
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
)

// NewConnector is a factory function that creates a new connector.Connector
// from the given options.
type NewConnector func(opts ...connector.Option) connector.Connector

// connectorRegistry stores connector factory functions. Duplicate registrations
// are treated as fatal errors (logger.Default().Fatal).
type connectorRegistry struct {
	registry[NewConnector]
}

// Register stores a connector factory under the given name. Calls Fatal on
// duplicate registration since connector names must be unique at init time.
func (r *connectorRegistry) Register(name string, v NewConnector) error {
	if err := r.registry.Register(name, v); err != nil {
		logger.Default().Fatal(err)
	}
	return nil
}
