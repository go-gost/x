package registry

import (
	"github.com/go-gost/core/service"
)

// serviceRegistry stores service.Service instances.
// It uses the base registry methods without a wrapper since services
// are looked up directly by name during startup.
type serviceRegistry struct {
	registry[service.Service]
}
