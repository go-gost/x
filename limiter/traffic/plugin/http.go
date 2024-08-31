package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/plugin"
	xtraffic "github.com/go-gost/x/limiter/traffic"
)

type httpPluginRequest struct {
	Service string `json:"service"`
	Scope   string `json:"scope"`
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Client  string `json:"client"`
	Src     string `json:"src"`
}

type httpPluginResponse struct {
	In  int64 `json:"in"`
	Out int64 `json:"out"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates a traffic limiter plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) traffic.TrafficLimiter {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":    "limiter",
			"limiter": name,
		}),
	}
}

func (p *httpPlugin) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.client == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Service: options.Service,
		Scope:   options.Scope,
		Network: options.Network,
		Addr:    options.Addr,
		Client:  options.Client,
		Src:     options.Src,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		p.log.Error(err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		p.log.Error(err)
		return nil
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Error(err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.log.Errorf("server return non-200 code: %s", resp.Status)
		return nil
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		p.log.Error(err)
		return nil
	}
	return xtraffic.NewLimiter(int(res.In))
}

func (p *httpPlugin) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.client == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Service: options.Service,
		Scope:   options.Scope,
		Network: options.Network,
		Addr:    options.Addr,
		Client:  options.Client,
		Src:     options.Src,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		p.log.Error(err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		p.log.Error(err)
		return nil
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Error(err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.log.Errorf("server return non-200 code: %s", resp.Status)
		return nil
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		p.log.Error(err)
		return nil
	}
	return xtraffic.NewLimiter(int(res.Out))
}
