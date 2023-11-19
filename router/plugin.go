package router

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	"github.com/go-gost/plugin/router/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.RouterClient
	log    logger.Logger
}

// NewGRPCPlugin creates an Router plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) router.Router {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "router",
		"router": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewRouterClient(conn)
	}
	return p
}

func (p *grpcPlugin) GetRoute(ctx context.Context, dst net.IP, opts ...router.Option) *router.Route {
	if p.client == nil {
		return nil
	}

	r, err := p.client.GetRoute(ctx,
		&proto.GetRouteRequest{
			Dst: dst.String(),
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}

	return ParseRoute(r.Net, r.Gateway)
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpPluginGetRouteRequest struct {
	Dst string `json:"dst"`
}

type httpPluginGetRouteResponse struct {
	Net     string `json:"net"`
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

func (p *httpPlugin) GetRoute(ctx context.Context, dst net.IP, opts ...router.Option) *router.Route {
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
	q.Set("dst", dst.String())
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

	return ParseRoute(res.Net, res.Gateway)
}
