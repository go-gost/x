package ingress

import (
	"context"
	"io"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/ingress/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.IngressClient
	log    logger.Logger
}

// NewGRPCPlugin creates an Ingress plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) ingress.Ingress {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":    "ingress",
		"ingress": name,
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
		p.client = proto.NewIngressClient(conn)
	}
	return p
}

func (p *grpcPlugin) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	if p.client == nil {
		return nil
	}

	r, err := p.client.GetRule(ctx,
		&proto.GetRuleRequest{
			Host: host,
		})
	if err != nil {
		p.log.Error(err)
		return nil
	}
	if r.Endpoint == "" {
		return nil
	}
	return &ingress.Rule{
		Hostname: host,
		Endpoint: r.Endpoint,
	}
}

func (p *grpcPlugin) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	if p.client == nil || rule == nil {
		return false
	}

	r, _ := p.client.SetRule(ctx, &proto.SetRuleRequest{
		Host:     rule.Hostname,
		Endpoint: rule.Endpoint,
	})
	if r == nil {
		return false
	}

	return r.Ok
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
