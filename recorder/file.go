package recorder

import (
	"context"
	"io"

	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/recorder"
	xmetrics "github.com/go-gost/x/metrics"
)

type fileRecorderOptions struct {
	recorder string
	sep      string
}

type FileRecorderOption func(opts *fileRecorderOptions)

func RecorderFileRecorderOption(recorder string) FileRecorderOption {
	return func(opts *fileRecorderOptions) {
		opts.recorder = recorder
	}
}

func SepFileRecorderOption(sep string) FileRecorderOption {
	return func(opts *fileRecorderOptions) {
		opts.sep = sep
	}
}

type fileRecorder struct {
	recorder string
	out      io.WriteCloser
	sep      string
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
	xmetrics.GetCounter(xmetrics.MetricRecorderRecordsCounter, metrics.Labels{"recorder": r.recorder}).Inc()

	if _, err := r.out.Write(b); err != nil {
		return err
	}

	if r.sep != "" {
		_, err := io.WriteString(r.out, r.sep)
		return err
	}

	return nil
}

func (r *fileRecorder) Close() error {
	return r.out.Close()
}
