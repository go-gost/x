package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginGetRuleRequest struct {
	Host string `json:"host"`
}

type httpPluginGetRuleResponse struct {
	Endpoint string `json:"endpoint"`
}

type httpPluginSetRuleRequest struct {
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
}

type httpPluginSetRuleResponse struct {
	OK bool `json:"ok"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Ingress plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) ingress.Ingress {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":    "ingress",
			"ingress": name,
		}),
	}
}

func (p *httpPlugin) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	if p.client == nil {
		return nil
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
	q.Set("host", host)
	req.URL.RawQuery = q.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	res := httpPluginGetRuleResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil
	}
	if res.Endpoint == "" {
		return nil
	}
	return &ingress.Rule{
		Hostname: host,
		Endpoint: res.Endpoint,
	}
}

func (p *httpPlugin) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	if p.client == nil || rule == nil {
		return false
	}

	rb := httpPluginSetRuleRequest{
		Host:     rule.Hostname,
		Endpoint: rule.Endpoint,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.url, bytes.NewReader(v))
	if err != nil {
		return false
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	res := httpPluginSetRuleResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false
	}
	return res.OK
}
