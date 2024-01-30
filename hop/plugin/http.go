package hop

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	node_parser "github.com/go-gost/x/config/parsing/node"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	Client  string `json:"client"`
	Src     string `json:"src"`
}

type httpPlugin struct {
	name   string
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Hop plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) hop.Hop {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		name:   name,
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind": "hop",
			"hop":  name,
		}),
	}
}

func (p *httpPlugin) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if p.client == nil {
		return nil
	}

	var options hop.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Network: options.Network,
		Addr:    options.Addr,
		Host:    options.Host,
		Path:    options.Path,
		Client:  string(ctxvalue.ClientIDFromContext(ctx)),
		Src:     string(ctxvalue.ClientAddrFromContext(ctx)),
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
		p.log.Error(resp.Status)
		return nil
	}

	var cfg config.NodeConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		p.log.Error(err)
		return nil
	}

	node, err := node_parser.ParseNode(p.name, &cfg, logger.Default())
	if err != nil {
		p.log.Error(err)
		return nil
	}
	return node
}
