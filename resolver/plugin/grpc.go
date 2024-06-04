package resolver

import (
	"context"
	"io"
	"net"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/plugin/resolver/proto"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.ResolverClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Resolver plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) (resolver.Resolver, error) {
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
	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewResolverClient(conn)
	}
	return p, nil
}

func (p *grpcPlugin) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) (ips []net.IP, err error) {
	p.log.Debugf("resolve %s/%s", host, network)

	if p.client == nil {
		return
	}

	r, err := p.client.Resolve(ctx,
		&proto.ResolveRequest{
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
	return
}

func (p *grpcPlugin) Close() error {
	if p.conn == nil {
		return nil
	}

	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
