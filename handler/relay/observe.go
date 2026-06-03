package relay

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/observer"
)

// checkRateLimit checks whether a new connection from addr should be accepted.
//
// If a RateLimiter is configured, it looks up the rate limiter for the client
// host and calls Allow(1). Without a RateLimiter or without a limiter for the
// specific host, the connection is allowed by default.
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

// observeStats is a background goroutine that periodically collects and pushes
// stats events. It is started in Init() when an Observer is configured.
//
// Event collection flow:
//
//	observeStats()
//	├─ ticker fires at observerPeriod intervals
//	├─ Each tick:
//	│   ├─ If previous events failed (events != nil):
//	│   │   └─ Retry sending buffered events
//	│   │       └─ If it fails again → continue (retain events for next tick)
//	│   ├─ Call h.stats.Events() for new events
//	│   ├─ If there are new events:
//	│   │   ├─ Try sending (Observe)
//	│   │   └─ If it fails → save to events, retry next tick
//	│   └─ On success, clear events = nil
//	└─ ctx.Done() → exit
//
// Retry mechanism:
//   - If Observe() returns an error, events are retained for the next retry.
//   - On retry, buffered events are sent first, then new events are fetched.
//   - This ensures events are not lost due to transient network issues.
func (h *relayHandler) observeStats(ctx context.Context) {
	if h.options.Observer == nil {
		return
	}

	// events holds events that failed to send on the previous tick, for retry.
	var events []observer.Event

	ticker := time.NewTicker(h.md.observerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// First, retry sending any buffered events from a previous failed attempt.
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err != nil {
					// Failed again, retain events for the next retry.
					continue
				}
			}

			// Fetch and send new events.
			if evs := h.stats.Events(); len(evs) > 0 {
				if err := h.options.Observer.Observe(ctx, evs); err != nil {
					// Failed, cache for retry on the next tick.
					events = evs
					continue
				}
			}
			// Sent successfully, clear the cache.
			events = nil

		case <-ctx.Done():
			return
		}
	}
}