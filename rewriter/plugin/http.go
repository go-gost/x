package rewriter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/rewriter"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Data     []byte `json:"data"`
	Metadata []byte `json:"metadata"`
}

type httpPluginResponse struct {
	OK   bool   `json:"ok"`
	Data []byte `json:"data"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates a Rewriter plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) rewriter.Rewriter {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "rewriter",
			"rewriter": name,
		}),
	}
}

func (p *httpPlugin) Rewrite(ctx context.Context, b []byte, opts ...rewriter.RewriteOption) ([]byte, error) {
	if p.client == nil {
		return b, nil
	}

	var options rewriter.RewriteOptions
	for _, opt := range opts {
		opt(&options)
	}

	md, err := json.Marshal(options.Metadata)
	if err != nil {
		return b, err
	}

	rb := httpPluginRequest{
		Data:     b,
		Metadata: md,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return b, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		return b, err
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return b, err
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return b, nil
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return b, err
	}

	if !res.OK {
		return b, nil
	}
	if res.Data != nil {
		return res.Data, nil
	}
	return b, nil
}
