package registry

import "github.com/go-gost/x/limiter/quota"

// quotaLimiterRegistry holds shared quota limiters; Unregister closes them.
type quotaLimiterRegistry struct {
	registry[*quota.Limiter]
}
