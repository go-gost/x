package hosts

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Network string `json:"network"`
	Host    string `json:"host"`
	Client  string `json:"client"`
}

type httpPluginResponse struct {
	IPs []string `json:"ips"`
	OK  bool     `json:"ok"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an HostMapper plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) hosts.HostMapper {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": name,
		}),
	}
}

func (p *httpPlugin) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) (ips []net.IP, ok bool) {
	p.log.Debugf("lookup %s/%s", host, network)

	if p.client == nil {
		return
	}

	rb := httpPluginRequest{
		Network: network,
		Host:    host,
		Client:  string(ctxvalue.ClientIDFromContext(ctx)),
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

	for _, s := range res.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, res.OK
}
