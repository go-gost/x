package conn

import (
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
	if atomic.AddInt64(&l.current, int64(n)) >= int64(l.limit) {
		if n > 0 {
			atomic.AddInt64(&l.current, -int64(n))
		}
		return false
	}
	return true
}
