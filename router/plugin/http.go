package router

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	"github.com/go-gost/x/internal/plugin"
	xrouter "github.com/go-gost/x/router"
)

type httpPluginGetRouteRequest struct {
	Dst string `json:"dst"`
	ID  string `json:"id"`
}

type httpPluginGetRouteResponse struct {
	Net     string `json:"net"`
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Router plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) router.Router {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "router",
			"router": name,
		}),
	}
}

func (p *httpPlugin) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
	if p.client == nil {
		return nil
	}

	var options router.Options
	for _, opt := range opts {
		opt(&options)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil
	}
	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Set("dst", dst)
	if options.ID != "" {
		q.Set("id", options.ID)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	res := httpPluginGetRouteResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil
	}

	dstNet := res.Dst
	if dstNet == "" {
		dstNet = res.Net
	}
	return xrouter.ParseRoute(dstNet, res.Gateway)
}
