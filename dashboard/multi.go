package dashboard

import (
	"context"
	"io"

	"github.com/go-gost/core/observer"
)

// Wrap returns the observer to attach to a service or handler. When the
// dashboard is disabled it returns next unchanged, so no extra goroutines or
// stats are created. When it is enabled, events go to the collector and to the
// configured observer, if any.
func Wrap(next observer.Observer) observer.Observer {
	if !Enabled() {
		return next
	}

	collector := Default()
	if next == nil {
		return collector
	}
	return &multi{collector: collector, next: next}
}

// multi fans events out to the collector and the configured observer. The
// collector's result is ignored (it never fails); the configured observer's
// error is propagated so its existing retry loop keeps working.
type multi struct {
	collector *Collector
	next      observer.Observer
}

func (m *multi) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	_ = m.collector.Observe(ctx, events, opts...)
	if m.next == nil {
		return nil
	}
	return m.next.Observe(ctx, events, opts...)
}

// Close closes the configured observer only. The collector does not implement
// io.Closer, so a collector shared by every service is never closed.
func (m *multi) Close() error {
	if c, ok := m.next.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
