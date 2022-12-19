package traffic

import (
	"context"
	"fmt"
	"sort"
	"strconv"

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
	return int(l.limiter.Limit())
}

func (l *llimiter) Set(n int) {
	l.limiter.SetLimit(rate.Limit(n))
	l.limiter.SetBurst(n)
}

func (l *llimiter) String() string {
	return strconv.Itoa(int(l.limiter.Limit()))
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

func (l *limiterGroup) Wait(ctx context.Context, n int) int {
	for i := range l.limiters {
		if v := l.limiters[i].Wait(ctx, n); v < n {
			n = v
		}
	}
	return n
}

func (l *limiterGroup) Limit() int {
	if len(l.limiters) == 0 {
		return 0
	}

	return l.limiters[0].Limit()
}

func (l *limiterGroup) Set(n int) {}

func (l *limiterGroup) String() string {
	return fmt.Sprintf("%v", l.limiters)
}
