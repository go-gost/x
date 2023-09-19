package hosts

import (
	"context"
	"io"
	"net"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/hosts/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"google.golang.org/grpc"
)

type grpcPluginHostMapper struct {
	conn   grpc.ClientConnInterface
	client proto.HostMapperClient
	log    logger.Logger
}

// NewGRPCPluginHostMapper creates a HostMapper plugin based on gRPC.
func NewGRPCPluginHostMapper(name string, conn grpc.ClientConnInterface) hosts.HostMapper {
	p := &grpcPluginHostMapper{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": name,
		}),
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
