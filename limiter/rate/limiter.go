package rate

import (
	"time"

	limiter "github.com/go-gost/core/limiter/rate"
	"golang.org/x/time/rate"
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
