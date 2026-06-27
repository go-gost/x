package rewriter

import (
	"context"
	"encoding/json"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/rewriter"
	"github.com/go-gost/plugin/rewriter/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.RewriterClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Rewriter plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) rewriter.Rewriter {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":     "rewriter",
		"rewriter": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}
	if conn == nil {
		return nil
	}

	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	p.client = proto.NewRewriterClient(conn)
	return p
}

func (p *grpcPlugin) Rewrite(ctx context.Context, b []byte, opts ...rewriter.RewriteOption) ([]byte, error) {
	if p.client == nil {
		return b, nil
	}

	var options rewriter.RewriteOptions
	for _, opt := range opts {
		opt(&options)
	}

	md, err := json.Marshal(options.Metadata)
	if err != nil {
		return b, err
	}

	reply, err := p.client.Rewrite(ctx,
		&proto.RewriteRequest{
			Data:     b,
			Metadata: md,
		})
	if err != nil {
		p.log.Error(err)
		return b, err
	}
	if reply == nil || !reply.Ok {
		return b, nil
	}
	if reply.Data != nil {
		return reply.Data, nil
	}
	return b, nil
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
