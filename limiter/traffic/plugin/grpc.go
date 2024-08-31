package traffic

import (
	"context"
	"io"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/limiter/traffic/proto"
	"github.com/go-gost/x/internal/plugin"
	xtraffic "github.com/go-gost/x/limiter/traffic"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.LimiterClient
	log    logger.Logger
}

// NewGRPCPlugin creates a traffic limiter plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) traffic.TrafficLimiter {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":    "limiter",
		"limiter": name,
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
		p.client = proto.NewLimiterClient(conn)
	}
	return p
}

func (p *grpcPlugin) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.client == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.Limit(ctx,
		&proto.LimitRequest{
			Service: options.Service,
			Scope:   options.Scope,
			Network: options.Network,
			Addr:    options.Addr,
			Client:  options.Client,
			Src:     options.Src,
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}

	return xtraffic.NewLimiter(int(r.In))
}

func (p *grpcPlugin) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	if p.client == nil {
		return nil
	}

	var options limiter.Options
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.Limit(ctx,
		&proto.LimitRequest{
			Service: options.Service,
			Scope:   options.Scope,
			Network: options.Network,
			Addr:    options.Addr,
			Client:  options.Client,
			Src:     options.Src,
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}

	return xtraffic.NewLimiter(int(r.Out))
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
