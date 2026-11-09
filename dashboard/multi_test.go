package dashboard

import (
	"context"
	"testing"

	"github.com/go-gost/core/observer"
)

type recordingObserver struct {
	calls int
}

func (o *recordingObserver) Observe(context.Context, []observer.Event, ...observer.Option) error {
	o.calls++
	return nil
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
