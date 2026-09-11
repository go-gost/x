// Package plugin implements p2p.TunnelProvider over the plugin control
// protocol (github.com/go-gost/plugin/p2p).
package plugin

import (
	"context"
	"errors"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/p2p/proto"
	xp2p "github.com/go-gost/x/p2p"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.P2PClient
	log    logger.Logger
}

// NewGRPCPlugin creates a p2p.TunnelProvider backed by a gRPC plugin. The
// constructor mirrors the recorder plugin's relaxed shape (connection
// failures are logged, a non-nil provider is always returned), but the
// runtime semantics are fail-closed: OpenTunnel/CloseTunnel on an
// unavailable plugin return errors, never no-ops.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) xp2p.TunnelProvider {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind": "p2p",
		"p2p":  name,
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
		p.client = proto.NewP2PClient(conn)
	}
	return p
}

func (p *grpcPlugin) OpenTunnel(ctx context.Context, network, peer string) (id, endpoint string, err error) {
	if p.client == nil {
		return "", "", errors.New("p2p: plugin unavailable")
	}
	reply, err := p.client.OpenTunnel(ctx, &proto.OpenTunnelRequest{Peer: peer, Network: network})
	if err != nil {
		p.log.Error(err)
		return "", "", err
	}
	if !reply.Ok {
		return "", "", errors.New(reply.Error)
	}
	return reply.Id, reply.Endpoint, nil
}

func (p *grpcPlugin) CloseTunnel(ctx context.Context, id string) error {
	if p.client == nil {
		return errors.New("p2p: plugin unavailable")
	}
	reply, err := p.client.CloseTunnel(ctx, &proto.CloseTunnelRequest{Id: id})
	if err != nil {
		p.log.Error(err)
		return err
	}
	if !reply.Ok {
		return errors.New("p2p: close tunnel failed")
	}
	return nil
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