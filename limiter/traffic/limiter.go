package traffic

import (
	"context"

	limiter "github.com/go-gost/core/limiter/traffic"
	"golang.org/x/time/rate"
)

type llimiter struct {
	limiter *rate.Limiter
}

func NewLimiter(r int) limiter.Limiter {
	return &llimiter{
		limiter: rate.NewLimiter(rate.Limit(r), r),
	}
}

func (l *llimiter) Wait(ctx context.Context, n int) int {
	if l.limiter.Burst() < n {
		n = l.limiter.Burst()
	}
	l.limiter.WaitN(ctx, n)
	return n
}

func (l *llimiter) Limit() int {
	return l.limiter.Burst()
}
