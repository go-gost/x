package registry

import (
	"github.com/go-gost/core/logger"
)

// loggerRegistry stores logger.Logger instances.
// It uses the base registry methods without a wrapper since loggers
// are looked up directly and do not need hot-reload proxying.
type loggerRegistry struct {
	registry[logger.Logger]
}

// Register stores a Logger under the given name.
func (r *loggerRegistry) Register(name string, v logger.Logger) error {
	return r.registry.Register(name, v)
}
