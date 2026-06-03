package relay

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/observer"
)

func (h *relayHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func (h *relayHandler) observeStats(ctx context.Context) {
	if h.options.Observer == nil {
		return
	}

	var events []observer.Event

	ticker := time.NewTicker(h.md.observerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Try to flush any buffered events from a previous failed attempt.
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err != nil {
					continue
				}
			}

			// Collect and send fresh events.
			if evs := h.stats.Events(); len(evs) > 0 {
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