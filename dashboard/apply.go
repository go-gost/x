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
)

// Apply synchronizes the dashboard with cfg. It stops any previous reporter,
// enables or disables the collector, clears stale series, and starts one
// reporter when enabled. It is safe to call on startup and on every reload.
func Apply(cfg *config.Config) {
	on := cfg != nil && cfg.Dashboard != nil && cfg.Dashboard.Enabled

	stopReporter()
	Enable(on)
	if !on {
		return
	}

	ResetState()
	startReporter()
}

func startReporter() {
	reporterMu.Lock()
	defer reporterMu.Unlock()

	if reporterCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	reporterCancel = cancel

	go func() {
		ticker := time.NewTicker(reportInterval)
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

func stopReporter() {
	reporterMu.Lock()
	defer reporterMu.Unlock()

	if reporterCancel != nil {
		reporterCancel()
		reporterCancel = nil
	}
}

func reporterActive() bool {
	reporterMu.Lock()
	defer reporterMu.Unlock()
	return reporterCancel != nil
}
