package loader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type httpLoaderOptions struct {
	timeout time.Duration
}

type HTTPLoaderOption func(opts *httpLoaderOptions)

func TimeoutHTTPLoaderOption(timeout time.Duration) HTTPLoaderOption {
	return func(opts *httpLoaderOptions) {
		opts.timeout = timeout
	}
}

type httpLoader struct {
	url        string
	httpClient *http.Client
}

// HTTPLoader loads data from HTTP request.
func HTTPLoader(url string, opts ...HTTPLoaderOption) Loader {
	var options httpLoaderOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return &httpLoader{
		url: url,
		httpClient: &http.Client{
			Timeout: options.timeout,
		},
	}
}

func (l *httpLoader) Load(ctx context.Context) (io.Reader, error) {
	req, err := http.NewRequest(http.MethodGet, l.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

func (l *httpLoader) Close() error {
	return nil
}
