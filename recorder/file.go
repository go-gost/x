package recorder

import (
	"context"
	"os"

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
	filename string
	sep      string
}

// FileRecorder records data to file.
func FileRecorder(filename string, opts ...FileRecorderOption) recorder.Recorder {
	var options fileRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &fileRecorder{
		filename: filename,
		sep:      options.sep,
	}
}

func (r *fileRecorder) Record(ctx context.Context, b []byte) error {
	f, err := os.OpenFile(r.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.Write(b); err != nil {
		return err
	}
	if r.sep != "" {
		_, err := f.WriteString(r.sep)
		return err
	}
	return nil
}

func (r *fileRecorder) Close() error {
	return nil
}
