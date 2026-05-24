package rate

import (
	"errors"
	"sort"
	"time"

	limiter "github.com/go-gost/core/limiter/rate"
	"golang.org/x/time/rate"
)

// ErrRateLimit is returned when a rate limit is exceeded.
var ErrRateLimit = errors.New("rate limit")

type rlimiter struct {
	limiter *rate.Limiter
}

// NewLimiter creates a [limiter.Limiter] with the specified rate r (events per second)
// and burst b.
func NewLimiter(r float64, b int) limiter.Limiter {
	return &rlimiter{
		limiter: rate.NewLimiter(rate.Limit(r), b),
	}
}

func (l *rlimiter) Allow(n int) bool {
	return l.limiter.AllowN(time.Now(), n)
}

func (l *rlimiter) Limit() float64 {
	return float64(l.limiter.Limit())
}

type limiterGroup struct {
	limiters []limiter.Limiter
}

func newLimiterGroup(limiters ...limiter.Limiter) *limiterGroup {
	sort.Slice(limiters, func(i, j int) bool {
		return limiters[i].Limit() < limiters[j].Limit()
	})
	return &limiterGroup{limiters: limiters}
}

func (l *limiterGroup) Allow(n int) bool {
	for i := range l.limiters {
		if !l.limiters[i].Allow(n) {
			return false
		}
	}
	return true
}

func (l *limiterGroup) Limit() float64 {
	if len(l.limiters) == 0 {
		return 0
	}

	return l.limiters[0].Limit()
}
