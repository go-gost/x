package dashboard

import (
	"io"

	conncore "github.com/go-gost/core/limiter/conn"
	ratecore "github.com/go-gost/core/limiter/rate"
	trafficcore "github.com/go-gost/core/limiter/traffic"
	limiterstats "github.com/go-gost/x/limiter/stats"
)

type limiterStatsProvider interface {
	Stats() limiterstats.Snapshot
}

func registerLimiterStats(set *seriesSet, provider limiterStatsProvider) {
	fn := func() LimiterStats {
		s := provider.Stats()
		return LimiterStats{
			Calls:     s.Calls,
			Allowed:   s.Allowed,
			Denied:    s.Denied,
			WaitCalls: s.WaitCalls,
			Requested: s.Requested,
			Granted:   s.Granted,
		}
	}
	set.get("").sampleLimiter.Store(&fn)
}

type connLimiterWrapper struct {
	conncore.ConnLimiter
	set *seriesSet
}

// WrapConnLimiter exposes aggregate connection limiter counters to the
// dashboard under the limiter_conn series.
func WrapConnLimiter(name string, next conncore.ConnLimiter) conncore.ConnLimiter {
	w := &connLimiterWrapper{ConnLimiter: next, set: newSeriesSet("limiter_conn", name)}
	if p, ok := next.(limiterStatsProvider); ok {
		registerLimiterStats(w.set, p)
	}
	return w
}

func (w *connLimiterWrapper) Close() error { return closeModule(w.ConnLimiter) }

type rateLimiterWrapper struct {
	ratecore.RateLimiter
	set *seriesSet
}

// WrapRateLimiter exposes aggregate rate limiter counters to the dashboard
// under the limiter_rate series.
func WrapRateLimiter(name string, next ratecore.RateLimiter) ratecore.RateLimiter {
	w := &rateLimiterWrapper{RateLimiter: next, set: newSeriesSet("limiter_rate", name)}
	if p, ok := next.(limiterStatsProvider); ok {
		registerLimiterStats(w.set, p)
	}
	return w
}

func (w *rateLimiterWrapper) Close() error { return closeModule(w.RateLimiter) }

type trafficLimiterWrapper struct {
	trafficcore.TrafficLimiter
	set *seriesSet
}

// WrapTrafficLimiter exposes aggregate traffic limiter counters to the
// dashboard under the limiter_traffic series.
func WrapTrafficLimiter(name string, next trafficcore.TrafficLimiter) trafficcore.TrafficLimiter {
	w := &trafficLimiterWrapper{TrafficLimiter: next, set: newSeriesSet("limiter_traffic", name)}
	if p, ok := next.(limiterStatsProvider); ok {
		registerLimiterStats(w.set, p)
	}
	return w
}

func (w *trafficLimiterWrapper) Close() error { return closeModule(w.TrafficLimiter) }

var (
	_ conncore.ConnLimiter       = (*connLimiterWrapper)(nil)
	_ io.Closer                  = (*connLimiterWrapper)(nil)
	_ ratecore.RateLimiter       = (*rateLimiterWrapper)(nil)
	_ io.Closer                  = (*rateLimiterWrapper)(nil)
	_ trafficcore.TrafficLimiter = (*trafficLimiterWrapper)(nil)
	_ io.Closer                  = (*trafficLimiterWrapper)(nil)
)
