package dashboard

import (
	"context"
	"errors"
	"testing"

	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/config"
	xstats "github.com/go-gost/x/observer/stats"
)

type recordingObserver struct {
	calls int
	err   error
}

func (o *recordingObserver) Observe(context.Context, []observer.Event, ...observer.Option) error {
	o.calls++
	return o.err
}

func TestWrapDisabledReturnsNext(t *testing.T) {
	Enable(false)
	next := &recordingObserver{}
	if got := Wrap(next); got != next {
		t.Fatal("Wrap must return the configured observer unchanged when disabled")
	}
}

func TestWrapEnabledFansOutToCollectorAndNext(t *testing.T) {
	Enable(true)
	defer Enable(false)

	next := &recordingObserver{}
	wrapped := Wrap(next)
	_ = wrapped.Observe(context.Background(), []observer.Event{
		ModuleStatsEvent{Kind: "bypass", Name: "direct", Calls: 1},
	})

	if next.calls != 1 {
		t.Fatalf("next observer calls = %d, want 1", next.calls)
	}
	if len(Default().Snapshot().Modules) != 1 {
		t.Fatal("collector did not receive the event")
	}
}

func TestWrapEnabledWithoutNextDoesNotPanic(t *testing.T) {
	Enable(true)
	defer Enable(false)

	if err := Wrap(nil).Observe(context.Background(), []observer.Event{unknownEvent{}}); err != nil {
		t.Fatal(err)
	}
}

func TestWrapPropagatesConfiguredObserverError(t *testing.T) {
	Enable(true)
	defer Enable(false)
	Default().Reset()

	want := errors.New("plugin down")
	next := &recordingObserver{err: want}
	err := Wrap(next).Observe(context.Background(), []observer.Event{
		ModuleStatsEvent{Kind: "bypass", Name: "direct", Calls: 1},
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if len(Default().Snapshot().Modules) != 1 {
		t.Fatal("dashboard lost the event when the configured observer failed")
	}
}

func TestApplyEnablesAndResets(t *testing.T) {
	Enable(false)
	Default().Reset()

	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	if !Enabled() {
		t.Fatal("Apply did not enable the dashboard")
	}
	_ = Default().Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "service", Service: "svc", InputBytes: 1},
	})

	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	if got := len(Default().Snapshot().Services); got != 0 {
		t.Fatalf("services after reload = %d, want 0", got)
	}

	Apply(nil)
	if Enabled() {
		t.Fatal("Apply did not disable the dashboard")
	}
}
