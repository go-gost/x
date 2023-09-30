package hop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/hop/proto"
	"github.com/go-gost/x/config"
	node_parser "github.com/go-gost/x/config/parsing/node"
	"github.com/go-gost/x/internal/plugin"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	name   string
	conn   grpc.ClientConnInterface
	client proto.HopClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Hop plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) hop.Hop {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind": "hop",
		"hop":  name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPlugin{
		name: name,
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewHopClient(conn)
	}
	return p
}

func (p *grpcPlugin) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if p.client == nil {
		return nil
	}

	var options hop.SelectOptions
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.Select(ctx,
		&proto.SelectRequest{
			Network: options.Network,
			Addr:    options.Addr,
			Host:    options.Host,
			Client:  string(auth_util.IDFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}

	if r.Node == nil {
		return nil
	}

	var cfg config.NodeConfig
	if err := json.NewDecoder(bytes.NewReader(r.Node)).Decode(&cfg); err != nil {
		p.log.Error(err)
		return nil
	}

	node, err := node_parser.ParseNode(p.name, &cfg)
	if err != nil {
		p.log.Error(err)
		return nil
	}
	return node
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpPluginRequest struct {
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Host    string `json:"host"`
	Client  string `json:"client"`
}

type httpPluginResponse struct {
	Node string `json:"node"`
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
		Client:  string(auth_util.IDFromContext(ctx)),
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		p.log.Error(err)
		return nil
	}

	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(v))
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

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		p.log.Error(resp.Status)
		return nil
	}

	if res.Node == "" {
		return nil
	}

	var cfg config.NodeConfig
	if err := json.NewDecoder(bytes.NewReader([]byte(res.Node))).Decode(&cfg); err != nil {
		p.log.Error(err)
		return nil
	}

	node, err := node_parser.ParseNode(p.name, &cfg)
	if err != nil {
		p.log.Error(err)
		return nil
	}
	return node
}
