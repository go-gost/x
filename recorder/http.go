package recorder

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-gost/core/recorder"
)

type httpRecorderOptions struct {
	timeout time.Duration
}

type HTTPRecorderOption func(opts *httpRecorderOptions)

func TimeoutHTTPRecorderOption(timeout time.Duration) HTTPRecorderOption {
	return func(opts *httpRecorderOptions) {
		opts.timeout = timeout
	}
}

type httpRecorder struct {
	url        string
	httpClient *http.Client
}

// HTTPRecorder records data to HTTP service.
func HTTPRecorder(url string, opts ...HTTPRecorderOption) recorder.Recorder {
	var options httpRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &httpRecorder{
		url: url,
		httpClient: &http.Client{
			Timeout: options.timeout,
		},
	}
}

func (r *httpRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	req, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(b))
	if err != nil {
		return err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
