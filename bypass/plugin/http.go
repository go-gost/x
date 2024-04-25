package bypass

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Client  string `json:"client"`
	Host    string `json:"host"`
	Path    string `json:"path"`
}

type httpPluginResponse struct {
	OK bool `json:"ok"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Bypass plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) bypass.Bypass {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": name,
		}),
	}
}

func (p *httpPlugin) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) (ok bool) {
	if p.client == nil {
		return
	}

	var options bypass.Options
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Network: network,
		Addr:    addr,
		Client:  string(ctxvalue.ClientIDFromContext(ctx)),
		Host:    options.Host,
		Path:    options.Path,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		return
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.OK
}

func (p *httpPlugin) IsWhitelist() bool {
	return false
}
