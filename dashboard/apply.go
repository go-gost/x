package dashboard

import (
	"context"
	"sync"
	"time"

	"github.com/go-gost/x/config"
)

var (
	reportInterval = 5 * time.Second

	reporterMu     sync.Mutex
	reporterCancel context.CancelFunc
	reporterDone   chan struct{}
)

// Apply synchronizes the dashboard with cfg. It stops and waits for any
// previous reporter, enables or disables the collector, clears stale series,
// and starts one reporter when enabled. It is safe to call on startup and on
// every reload.
func Apply(cfg *config.Config) {
	on := cfg != nil && cfg.Dashboard != nil && cfg.Dashboard.Enabled

	stopReporter()
	Enable(on)
	ResetState()
	Default().SetChainFilter(chainNames(cfg))

	if on {
		startReporter()
	}
}

// chainNames returns the set of chain names defined in cfg. A nil cfg means
// no filtering; a non-nil cfg with no chains filters out every chain.
func chainNames(cfg *config.Config) map[string]struct{} {
	if cfg == nil {
		return nil
	}
	names := make(map[string]struct{}, len(cfg.Chains))
	for _, c := range cfg.Chains {
		if c.Name != "" {
			names[c.Name] = struct{}{}
		}
	}
	return names
}

func startReporter() {
	reporterMu.Lock()
	defer reporterMu.Unlock()

	if reporterCancel != nil {
		return
	}

	interval := reportInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	reporterCancel = cancel
	reporterDone = done

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				Flush()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// stopReporter cancels the reporter and waits for the goroutine to exit, so an
// in-flight Flush cannot write into the next config's collector after reset.
func stopReporter() {
	reporterMu.Lock()
	cancel := reporterCancel
	done := reporterDone
	reporterCancel = nil
	reporterDone = nil
	reporterMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func reporterActive() bool {
	reporterMu.Lock()
	defer reporterMu.Unlock()
	return reporterCancel != nil
}
