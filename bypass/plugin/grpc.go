package bypass

import (
	"context"
	"io"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/bypass/proto"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.BypassClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Bypass plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) bypass.Bypass {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "bypass",
		"bypass": name,
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
		p.client = proto.NewBypassClient(conn)
	}
	return p
}

func (p *grpcPlugin) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if p.client == nil {
		return true
	}

	var options bypass.Options
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.Bypass(ctx,
		&proto.BypassRequest{
			Network: network,
			Addr:    addr,
			Client:  string(ctxvalue.ClientIDFromContext(ctx)),
			Host:    options.Host,
			Path:    options.Path,
		})
	if err != nil {
		p.log.Error(err)
		return true
	}
	return r.Ok
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (p *grpcPlugin) IsWhitelist() bool {
	return false
}
