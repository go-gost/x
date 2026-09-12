// Package plugin implements p2p.TunnelProvider over the plugin control
// protocol (github.com/go-gost/plugin/p2p).
package plugin

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/p2p/proto"
	"github.com/go-gost/x/internal/plugin"
	xp2p "github.com/go-gost/x/p2p"
	"github.com/go-gost/x/p2p/streamconn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// rpcTimeout caps the control RPC (OpenTunnel) with a fresh context so a
// wedged plugin cannot stall a dial.
const rpcTimeout = 3 * time.Second

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.P2PClient
	log    logger.Logger
}

// NewGRPCPlugin creates a p2p.TunnelProvider backed by a gRPC plugin. The
// constructor mirrors the recorder plugin's relaxed shape (connection
// failures are logged, a non-nil provider is always returned), but the
// runtime semantics are fail-closed: OpenTunnelStream on an unavailable
// plugin returns an error, never a no-op.
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

// OpenTunnelStream runs the two-RPC tunnel setup: OpenTunnel authorizes the
// tunnel and issues its id (the stream credential), then the Tunnel bidi
// stream — bound to the id via the "id" metadata key — carries the data. The
// returned conn's Close ends the stream, which the host treats as the tunnel
// teardown.
func (p *grpcPlugin) OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error) {
	if p.client == nil {
		return nil, errors.New("p2p: plugin unavailable")
	}

	octx, cancel := context.WithTimeout(ctx, rpcTimeout)
	reply, err := p.client.OpenTunnel(octx, &proto.OpenTunnelRequest{Peer: peer, Network: network})
	cancel()
	if err != nil {
		p.log.Error(err)
		return nil, err
	}
	if !reply.Ok {
		return nil, errors.New(reply.Error)
	}

	// The stream outlives Dial: derive its context from Background, not the
	// dial ctx. Its cancel is the conn's abort — cancelling the client stream
	// unblocks a parked Recv/Send and tells the host to tear the tunnel down.
	sctx, scancel := context.WithCancel(context.Background())
	sctx = metadata.AppendToOutgoingContext(sctx, "id", reply.Id)

	// Bound the establishment: a wedged plugin must not hang Dial (which
	// holds the base dialer's lock) waiting for a transport that never comes.
	estTimer := time.AfterFunc(rpcTimeout, scancel)
	stream, err := p.client.Tunnel(sctx)
	if !estTimer.Stop() && err == nil {
		// The timer fired while the stream was being established: scancel has
		// run, so the stream is canceled and unusable — fail instead of
		// returning a dead conn.
		err = errors.New("p2p: tunnel stream establishment timed out")
	}
	if err != nil {
		scancel()
		p.log.Error(err)
		return nil, err
	}
	return streamconn.New(stream, scancel, network,
		streamAddr{network: network, addr: "p2p"},
		streamAddr{network: network, addr: peer}), nil
}

// streamAddr is the synthetic address of a gRPC-carried tunnel. The stream
// has no socket, but callers read LocalAddr/RemoteAddr (e.g. the udp dialer's
// ReadFrom), so they must be non-nil.
type streamAddr struct {
	network string
	addr    string
}

func (a streamAddr) Network() string { return a.network }
func (a streamAddr) String() string  { return a.addr }

func (p *grpcPlugin) Close() error {
	if p.conn == nil {
		return nil
	}

	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
