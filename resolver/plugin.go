package resolver

import (
	"context"
	"io"
	"net"

	"github.com/go-gost/core/logger"
	resolver_pkg "github.com/go-gost/core/resolver"
	"github.com/go-gost/plugin/resolver/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"google.golang.org/grpc"
)

type grpcPluginResolver struct {
	conn   grpc.ClientConnInterface
	client proto.ResolverClient
	log    logger.Logger
}

// NewGRPCPluginResolver creates a Resolver plugin based on gRPC.
func NewGRPCPluginResolver(name string, conn grpc.ClientConnInterface) (resolver_pkg.Resolver, error) {
	p := &grpcPluginResolver{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "resolver",
			"resolver": name,
		}),
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
