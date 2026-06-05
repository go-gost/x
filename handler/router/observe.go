package router

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/observer"
)

// checkRateLimit applies connection-level rate limiting based on the
// client's remote address.
//
// The rate limiter key is the host portion of the remote address.
// If no rate limiter is configured, all connections are allowed.
func (h *routerHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

// observeStats periodically collects traffic statistics and reports them
// to the configured observer.
//
// The collection period is controlled by metadata.observerPeriod
// (default: 5s, minimum: 1s).
//
// # Retry behavior
//
// If observation fails (e.g., observer backend is temporarily
// unavailable), the events are buffered and retried on the next tick.
// During retry, new events are NOT collected — this prevents
// unbounded accumulation while the backend is unhealthy. Once the
// buffered events are successfully sent, the next tick resumes
// normal collection.
//
// This pattern is used consistently across all handler packages
// (http, http2, socks4/5, relay, tunnel, router, etc.).
func (h *routerHandler) observeStats(ctx context.Context) {
	if h.options.Observer == nil {
		return
	}

	var events []observer.Event

	ticker := time.NewTicker(h.md.observerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Retry buffered events from a previous failed attempt first.
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err != nil {
					continue
				}
			}

			// Collect and send fresh events.
			evs := h.stats.Events()
			if len(evs) > 0 {
				if err := h.options.Observer.Observe(ctx, evs); err != nil {
					events = evs
					continue
				}
			}
			events = nil

		case <-ctx.Done():
			return
		}
	}
}
