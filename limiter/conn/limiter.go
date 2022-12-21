package conn

import (
	"sort"
	"sync/atomic"

	limiter "github.com/go-gost/core/limiter/conn"
)

type llimiter struct {
	limit   int
	current int64
}

func NewLimiter(n int) limiter.Limiter {
	return &llimiter{limit: n}
}

func (l *llimiter) Limit() int {
	return l.limit
}

func (l *llimiter) Allow(n int) bool {
	if atomic.AddInt64(&l.current, int64(n)) > int64(l.limit) {
		if n > 0 {
			atomic.AddInt64(&l.current, -int64(n))
		}
		return false
	}
	return true
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
	var i int

	for i = range l.limiters {
		if b = l.limiters[i].Allow(n); !b {
			break
		}
	}
	if !b && i > 0 && n > 0 {
		for i := range l.limiters[:i] {
			l.limiters[i].Allow(-n)
		}
	}

	return
}

func (l *limiterGroup) Limit() int {
	if len(l.limiters) == 0 {
		return 0
	}

	return l.limiters[0].Limit()
}
