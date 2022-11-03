package registry

import (
	"github.com/go-gost/core/service"
)

type serviceRegistry struct {
	registry[service.Service]
}
