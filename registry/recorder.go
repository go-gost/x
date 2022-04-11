package registry

import (
	"context"

	"github.com/go-gost/core/recorder"
)

type recorderRegistry struct {
	registry
}

func (r *recorderRegistry) Register(name string, v recorder.Recorder) error {
	return r.registry.Register(name, v)
}

func (r *recorderRegistry) Get(name string) recorder.Recorder {
	if name != "" {
		return &recorderWrapper{name: name, r: r}
	}
	return nil
}

func (r *recorderRegistry) get(name string) recorder.Recorder {
	if v := r.registry.Get(name); v != nil {
		return v.(recorder.Recorder)
	}
	return nil
}

type recorderWrapper struct {
	name string
	r    *recorderRegistry
}

func (w *recorderWrapper) Record(ctx context.Context, b []byte) error {
	v := w.r.get(w.name)
	if v == nil {
		return nil
	}
	return v.Record(ctx, b)
}
