package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/plugin/resolver/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginResolver struct {
	conn   grpc.ClientConnInterface
	client proto.ResolverClient
	log    logger.Logger
}

// NewGRPCPluginResolver creates a Resolver plugin based on gRPC.
func NewGRPCPluginResolver(name string, addr string, opts ...plugin.Option) (resolver.Resolver, error) {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":      "resolver",
		"resolover": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}
	p := &grpcPluginResolver{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewResolverClient(conn)
	}
	return p, nil
}

func (p *grpcPluginResolver) Resolve(ctx context.Context, network, host string) (ips []net.IP, err error) {
	p.log.Debugf("resolve %s/%s", host, network)

	if p.client == nil {
		return
	}

	r, err := p.client.Resolve(context.Background(),
		&proto.ResolveRequest{
			Network: network,
			Host:    host,
			Client:  string(auth_util.IDFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return
	}
	for _, s := range r.Ips {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return
}

func (p *grpcPluginResolver) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpResolverRequest struct {
	Network string `json:"network"`
	Host    string `json:"host"`
	Client  string `json:"client"`
}

type httpResolverResponse struct {
	IPs []string `json:"ips"`
	OK  bool     `json:"ok"`
}

type httpPluginResolver struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginResolver creates an Resolver plugin based on HTTP.
func NewHTTPPluginResolver(name string, url string, opts ...plugin.Option) resolver.Resolver {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginResolver{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "resolver",
			"resolver": name,
		}),
	}
}

func (p *httpPluginResolver) Resolve(ctx context.Context, network, host string) (ips []net.IP, err error) {
	p.log.Debugf("resolve %s/%s", host, network)

	if p.client == nil {
		return
	}

	rb := httpResolverRequest{
		Network: network,
		Host:    host,
		Client:  string(auth_util.IDFromContext(ctx)),
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
		err = fmt.Errorf("%s", resp.Status)
		return
	}

	res := httpResolverResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}

	if !res.OK {
		return nil, errors.New("resolve failed")
	}

	for _, s := range res.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
