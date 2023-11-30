//go:build !linux

package router

import (
	"github.com/go-gost/core/router"
)

func (*localRouter) setSysRoutes(routes ...*router.Route) error {
	return nil
}
