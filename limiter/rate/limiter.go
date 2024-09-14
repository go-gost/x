package rate

import (
	"errors"
	"sort"
	"time"

	limiter "github.com/go-gost/core/limiter/rate"
	"golang.org/x/time/rate"
)

var (
	ErrRateLimit = errors.New("rate limit")
)

type rlimiter struct {
	limiter *rate.Limiter
}

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

func (l *limiterGroup) Allow(n int) (b bool) {
	b = true
	for i := range l.limiters {
		if v := l.limiters[i].Allow(n); !v {
			b = false
		}
	}
	return
}

func (l *limiterGroup) Limit() float64 {
	if len(l.limiters) == 0 {
		return 0
	}

	return l.limiters[0].Limit()
}
