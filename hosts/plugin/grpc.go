package hosts

import (
	"context"
	"io"
	"net"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/hosts/proto"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

// grpcPlugin is a HostMapper that delegates lookups to a remote gRPC service.
type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.HostMapperClient
	log    logger.Logger
}

// NewGRPCPlugin creates a HostMapper plugin that delegates lookups to a remote gRPC endpoint.
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

// Lookup calls the gRPC HostMapper service and returns the resolved IPs.
func (p *grpcPlugin) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) (ips []net.IP, ok bool) {
	p.log.Debugf("lookup %s/%s", host, network)

	if p.client == nil {
		return
	}

	r, err := p.client.Lookup(ctx,
		&proto.LookupRequest{
			Network: network,
			Host:    host,
			Client:  string(ctxvalue.ClientIDFromContext(ctx)),
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

// Close closes the underlying gRPC connection.
func (p *grpcPlugin) Close() error {
	if p.conn == nil {
		return nil
	}

	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
