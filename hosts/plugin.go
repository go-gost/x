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
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.HostMapperClient
	log    logger.Logger
}

// NewGRPCPlugin creates a HostMapper plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) hosts.HostMapper {
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
	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewHostMapperClient(conn)
	}
	return p
}

func (p *grpcPlugin) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) (ips []net.IP, ok bool) {
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

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

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
