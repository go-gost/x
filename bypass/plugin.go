package bypass

import (
	"context"
	"io"

	bypass_pkg "github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/bypass/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"google.golang.org/grpc"
)

type grpcPluginBypass struct {
	conn   grpc.ClientConnInterface
	client proto.BypassClient
	log    logger.Logger
}

// NewGRPCPluginBypass creates a Bypass plugin based on gRPC.
func NewGRPCPluginBypass(name string, conn grpc.ClientConnInterface) bypass_pkg.Bypass {
	p := &grpcPluginBypass{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": name,
		}),
	}
	if conn != nil {
		p.client = proto.NewBypassClient(conn)
	}
	return p
}

func (p *grpcPluginBypass) Contains(ctx context.Context, addr string) bool {
	if p.client == nil {
		return true
	}

	r, err := p.client.Bypass(ctx,
		&proto.BypassRequest{
			Addr:   addr,
			Client: string(auth_util.IDFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return true
	}
	return r.Ok
}

func (p *grpcPluginBypass) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
