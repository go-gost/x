package hosts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/hosts/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginHostMapper struct {
	conn   grpc.ClientConnInterface
	client proto.HostMapperClient
	log    logger.Logger
}

// NewGRPCPluginHostMapper creates a HostMapper plugin based on gRPC.
func NewGRPCPluginHostMapper(name string, addr string, opts ...plugin.Option) hosts.HostMapper {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":  "hosts",
		"hosts": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}
	p := &grpcPluginHostMapper{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewHostMapperClient(conn)
	}
	return p
}

func (p *grpcPluginHostMapper) Lookup(ctx context.Context, network, host string) (ips []net.IP, ok bool) {
	p.log.Debugf("lookup %s/%s", host, network)

	if p.client == nil {
		return
	}

	r, err := p.client.Lookup(ctx,
		&proto.LookupRequest{
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
	ok = r.Ok
	return
}

func (p *grpcPluginHostMapper) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpHostMapperRequest struct {
	Network string `json:"network"`
	Host    string `json:"host"`
	Client  string `json:"client"`
}

type httpHostMapperResponse struct {
	IPs []string `json:"ips"`
	OK  bool     `json:"ok"`
}

type httpPluginHostMapper struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginHostMapper creates an HostMapper plugin based on HTTP.
func NewHTTPPluginHostMapper(name string, url string, opts ...plugin.Option) hosts.HostMapper {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginHostMapper{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": name,
		}),
	}
}

func (p *httpPluginHostMapper) Lookup(ctx context.Context, network, host string) (ips []net.IP, ok bool) {
	p.log.Debugf("lookup %s/%s", host, network)

	if p.client == nil {
		return
	}

	rb := httpHostMapperRequest{
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
		return
	}

	res := httpHostMapperResponse{}
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
