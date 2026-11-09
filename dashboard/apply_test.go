package dashboard

import (
	"testing"
	"time"

	"github.com/go-gost/x/config"
)

func enabledConfig() *config.Config {
	return &config.Config{Dashboard: &config.DashboardConfig{Enabled: true}}
}

func TestStopReporterWaitsForExit(t *testing.T) {
	stopReporter()

	done := make(chan struct{})
	reporterMu.Lock()
	reporterCancel = func() {}
	reporterDone = done
	reporterMu.Unlock()

	returned := make(chan struct{})
	go func() {
		stopReporter()
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("stopReporter returned before the reporter goroutine exited")
	case <-time.After(20 * time.Millisecond):
	}

	close(done)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stopReporter did not return after the reporter exited")
	}
}

func TestApplyTwiceKeepsOneReporter(t *testing.T) {
	Apply(enabledConfig())
	t.Cleanup(func() { Apply(nil) })

	Apply(enabledConfig())
	if !reporterActive() {
		t.Fatal("reporter not active after a second Apply")
	}
}

func TestReloadClearsOldSeries(t *testing.T) {
	Apply(enabledConfig())
	t.Cleanup(func() { Apply(nil) })

	set := newSeriesSet("bypass", "old")
	set.get("svc").calls.Add(1)

	Apply(enabledConfig())
	Flush()
	if got := len(Default().Snapshot().Modules); got != 0 {
		t.Fatalf("modules after reload = %d, want 0", got)
	}
}

func TestApplyStartsAndStopsReporter(t *testing.T) {
	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	t.Cleanup(func() { Apply(nil) })

	if !reporterActive() {
		t.Fatal("reporter not started")
	}

	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: false}})
	if reporterActive() {
		t.Fatal("reporter not stopped")
	}
}
