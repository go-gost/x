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

// httpPluginRequest is the JSON payload sent to a remote HTTP bypass service.
type httpPluginRequest struct {
	Service string `json:"service"`
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Client  string `json:"client"`
	Host    string `json:"host"`
	Path    string `json:"path"`
}

// httpPluginResponse is the JSON response from a remote HTTP bypass service.
type httpPluginResponse struct {
	OK bool `json:"ok"`
}

// httpPlugin delegates bypass decisions to a remote HTTP service.
// All error paths return true (fail-open) so that a down plugin
// does not block traffic.
type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates a Bypass that delegates decisions to an HTTP
// bypass service at url. The service should accept POST requests with
// a JSON body and return {"ok": true/false}.
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

func (p *httpPlugin) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if p.client == nil {
		return true
	}

	log := p.log
	if log == nil {
		log = logger.Default()
	}

	var options bypass.Options
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Service: options.Service,
		Network: network,
		Addr:    addr,
		Client:  string(ctxvalue.ClientIDFromContext(ctx)),
		Host:    options.Host,
		Path:    options.Path,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		log.Error(err)
		return true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		log.Error(err)
		return true
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		log.Error(err)
		return true
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return true
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Error(err)
		return true
	}
	return res.OK
}

func (p *httpPlugin) Close() error {
	if p.client != nil {
		if tr := plugin.HTTPClientTransport(p.client); tr != nil {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

func (p *httpPlugin) IsWhitelist() bool {
	return false
}
