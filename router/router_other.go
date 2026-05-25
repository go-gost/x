//go:build !linux

package router

import (
	"github.com/go-gost/core/router"
)

// setSysRoutes is a no-op on non-Linux platforms.
func (*localRouter) setSysRoutes(routes ...*router.Route) error {
	return nil
}
