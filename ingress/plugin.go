package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/ingress/proto"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginIngress struct {
	conn   grpc.ClientConnInterface
	client proto.IngressClient
	log    logger.Logger
}

// NewGRPCPluginIngress creates an Ingress plugin based on gRPC.
func NewGRPCPluginIngress(name string, addr string, opts ...plugin.Option) ingress.Ingress {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":    "ingress",
		"ingress": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPluginIngress{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewIngressClient(conn)
	}
	return p
}

func (p *grpcPluginIngress) Get(ctx context.Context, host string) string {
	if p.client == nil {
		return ""
	}

	r, err := p.client.Get(ctx,
		&proto.GetRequest{
			Host: host,
		})
	if err != nil {
		p.log.Error(err)
		return ""
	}
	return r.GetEndpoint()
}

func (p *grpcPluginIngress) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpIngressRequest struct {
	Host string `json:"host"`
}

type httpIngressResponse struct {
	Endpoint string `json:"endpoint"`
}

type httpPluginIngress struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginIngress creates an Ingress plugin based on HTTP.
func NewHTTPPluginIngress(name string, url string, opts ...plugin.Option) ingress.Ingress {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginIngress{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":    "ingress",
			"ingress": name,
		}),
	}
}

func (p *httpPluginIngress) Get(ctx context.Context, host string) (endpoint string) {
	if p.client == nil {
		return
	}

	rb := httpIngressRequest{
		Host: host,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(v))
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

	res := httpIngressResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.Endpoint
}
