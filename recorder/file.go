package recorder

import (
	"context"
	"io"

	"github.com/go-gost/core/recorder"
)

type fileRecorderOptions struct {
	sep string
}

type FileRecorderOption func(opts *fileRecorderOptions)

func SepRecorderOption(sep string) FileRecorderOption {
	return func(opts *fileRecorderOptions) {
		opts.sep = sep
	}
}

type fileRecorder struct {
	out io.WriteCloser
	sep string
}

// FileRecorder records data to file.
func FileRecorder(out io.WriteCloser, opts ...FileRecorderOption) recorder.Recorder {
	var options fileRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &fileRecorder{
		out: out,
		sep: options.sep,
	}
}

func (r *fileRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
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
