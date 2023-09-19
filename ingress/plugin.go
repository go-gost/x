package ingress

import (
	"context"
	"io"

	ingress_pkg "github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/ingress/proto"
	"google.golang.org/grpc"
)

type grpcPluginIngress struct {
	conn   grpc.ClientConnInterface
	client proto.IngressClient
	log    logger.Logger
}

// NewGRPCPluginIngress creates a ingress plugin based on gRPC.
func NewGRPCPluginIngress(name string, conn grpc.ClientConnInterface) ingress_pkg.Ingress {
	p := &grpcPluginIngress{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":    "ingress",
			"ingress": name,
		}),
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
