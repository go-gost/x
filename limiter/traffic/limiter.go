package traffic

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	limiter "github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/x/limiter/stats"
	"golang.org/x/time/rate"
)

type llimiter struct {
	limiter *rate.Limiter
	stats   *stats.Stats
}

// NewLimiter creates a rate-based traffic Limiter with the given rate
// (bytes per second). The burst size is set equal to the rate.
func NewLimiter(r int) limiter.Limiter {
	return newLimiter(r, nil)
}

func newLimiter(r int, st *stats.Stats) limiter.Limiter {
	return &llimiter{
		limiter: rate.NewLimiter(rate.Limit(r), r),
		stats:   st,
	}
}

// NewLimiterWithBurst creates a rate-based traffic Limiter with the given rate
// (bytes per second) and burst size. If burst <= 0, it defaults to r.
func NewLimiterWithBurst(r, burst int) limiter.Limiter {
	return newLimiterWithBurst(r, burst, nil)
}

func newLimiterWithBurst(r, burst int, st *stats.Stats) limiter.Limiter {
	if burst <= 0 {
		burst = r
	}
	return &llimiter{
		limiter: rate.NewLimiter(rate.Limit(r), burst),
		stats:   st,
	}
}

func (l *llimiter) Wait(ctx context.Context, n int) int {
	if n <= 0 {
		return 0
	}
	l.stats.Wait(n)
	burst := l.limiter.Burst()
	if n > burst {
		n = burst
	}
	if err := l.limiter.WaitN(ctx, n); err != nil {
		l.stats.Deny()
		return 0
	}
	l.stats.Grant(n)
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
