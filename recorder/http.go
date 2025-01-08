package recorder

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-gost/core/recorder"
)

type httpRecorderOptions struct {
	timeout time.Duration
	header  http.Header
}

type HTTPRecorderOption func(opts *httpRecorderOptions)

func TimeoutHTTPRecorderOption(timeout time.Duration) HTTPRecorderOption {
	return func(opts *httpRecorderOptions) {
		opts.timeout = timeout
	}
}

func HeaderHTTPRecorderOption(header http.Header) HTTPRecorderOption {
	return func(opts *httpRecorderOptions) {
		opts.header = header
	}
}

type httpRecorder struct {
	url        string
	httpClient *http.Client
	header     http.Header
}

// HTTPRecorder records data to HTTP service.
func HTTPRecorder(url string, opts ...HTTPRecorderOption) recorder.Recorder {
	var options httpRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	if url == "" {
		return nil
	}
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	return &httpRecorder{
		url: url,
		httpClient: &http.Client{
			Timeout: options.timeout,
		},
		header: options.header,
	}
}

func (r *httpRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	req, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(b))
	if err != nil {
		return err
	}

	if r.header != nil {
		req.Header = r.header
	}

	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return errors.New(resp.Status)
	}

	return nil
}
