package registry

import (
	"context"

	"github.com/go-gost/core/recorder"
)

// recorderRegistry implements a hot-reload-safe registry for recorder.Recorder.
type recorderRegistry struct {
	registry[recorder.Recorder]
}

// Register stores a Recorder under the given name.
func (r *recorderRegistry) Register(name string, v recorder.Recorder) error {
	return r.registry.Register(name, v)
}

// Get returns a wrapper that delegates to the currently registered Recorder.
// Returns nil if name is empty.
func (r *recorderRegistry) Get(name string) recorder.Recorder {
	if name != "" {
		return &recorderWrapper{name: name, r: r}
	}
	return nil
}

func (r *recorderRegistry) get(name string) recorder.Recorder {
	return r.registry.Get(name)
}

type recorderWrapper struct {
	name string
	r    *recorderRegistry
}

func (w *recorderWrapper) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Record(ctx, b, opts...)
}
