package dashboard

import (
	"context"
	"errors"
	"io"

	"github.com/go-gost/core/observer"
)

// Wrap returns the observer to attach to a service or handler. When the
// dashboard is disabled it returns next unchanged, so no extra goroutines or
// stats are created. When it is enabled, events fan out to the collector and
// to the configured observer, if any.
func Wrap(next observer.Observer) observer.Observer {
	if !Enabled() {
		return next
	}

	collector := Default()
	if next == nil {
		return collector
	}
	return &multi{observers: []observer.Observer{collector, next}}
}

// multi fans events out to several observers. Dashboard failures never fail
// the batch, because callers retry failed batches and would duplicate work.
type multi struct {
	observers []observer.Observer
}

func (m *multi) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	for _, o := range m.observers {
		if o == nil {
			continue
		}
		_ = o.Observe(ctx, events, opts...)
	}
	return nil
}

// Close closes the configured observers. The collector does not implement
// io.Closer, so a shared collector is never closed by one service.
func (m *multi) Close() error {
	var errs []error
	for _, o := range m.observers {
		if c, ok := o.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
