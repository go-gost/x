package router

import (
	"context"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	"github.com/go-gost/plugin/router/proto"
	"github.com/go-gost/x/internal/plugin"
	xrouter "github.com/go-gost/x/router"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.RouterClient
	log    logger.Logger
}

// NewGRPCPlugin creates an Router plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) router.Router {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "router",
		"router": name,
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
		p.client = proto.NewRouterClient(conn)
	}
	return p
}

func (p *grpcPlugin) GetRoute(ctx context.Context, dst string, opts ...router.Option) *router.Route {
	if p.client == nil {
		return nil
	}

	var options router.Options
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.GetRoute(ctx,
		&proto.GetRouteRequest{
			Dst: dst,
			Id:  options.ID,
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}

	return xrouter.ParseRoute(r.Dst, r.Gateway)
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
