package recorder

import (
	"context"
	"io"
	"sync"

	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/recorder"
	xmetrics "github.com/go-gost/x/metrics"
)

type fileRecorderOptions struct {
	recorder string
	sep      string
}

// FileRecorderOption configures FileRecorder options.
type FileRecorderOption func(opts *fileRecorderOptions)

// RecorderFileRecorderOption sets the recorder name for metrics labeling.
func RecorderFileRecorderOption(recorder string) FileRecorderOption {
	return func(opts *fileRecorderOptions) {
		opts.recorder = recorder
	}
}

// SepFileRecorderOption sets the record separator written after each record.
func SepFileRecorderOption(sep string) FileRecorderOption {
	return func(opts *fileRecorderOptions) {
		opts.sep = sep
	}
}

type fileRecorder struct {
	recorder string
	out      io.WriteCloser
	sep      string

	mu        sync.Mutex
	closeOnce sync.Once
}

// FileRecorder records data to file.
func FileRecorder(out io.WriteCloser, opts ...FileRecorderOption) recorder.Recorder {
	var options fileRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &fileRecorder{
		recorder: options.recorder,
		out:      out,
		sep:      options.sep,
	}
}

func (r *fileRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if r.out == nil {
		return nil
	}

	xmetrics.GetCounter(xmetrics.MetricRecorderRecordsCounter, metrics.Labels{"recorder": r.recorder}).Inc()

	// ponytail: serializes every Record. Required for correctness: the underlying
	// io.WriteCloser (bytes.Buffer, *os.File, ...) is not safe for concurrent Write,
	// and Record is invoked concurrently from per-connection goroutines. If a single
	// recorder ever becomes a hot bottleneck, the upgrade path is an async/batched
	// writer — not per-record locking. Kept as a global lock because recorder write
	// rate is low (one record per forwarded transaction).
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.out.Write(b); err != nil {
		return err
	}

	if r.sep != "" {
		if _, err := io.WriteString(r.out, r.sep); err != nil {
			return err
		}
	}

	return nil
}

func (r *fileRecorder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		if r.out != nil {
			err = r.out.Close()
		}
	})
	return err
}
