package bypass

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	"github.com/go-gost/core/bypass"
	corelogger "github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/bypass/proto"
	"github.com/go-gost/x/internal/plugin"
	xlogger "github.com/go-gost/x/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) {
	corelogger.SetDefault(xlogger.Nop())
	os.Exit(m.Run())
}

// helper to set up a real gRPC server on a random port, returning the client conn and server stop func.
func newTestGRPCConn(t *testing.T, srv proto.BypassServer) (*grpc.ClientConn, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gsrv := grpc.NewServer()
	proto.RegisterBypassServer(gsrv, srv)
	go gsrv.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	return conn, func() {
		conn.Close()
		gsrv.Stop()
	}
}

func TestGRPCPlugin_FailOpen_NilClient(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.NoError(t, p.Close())
}

func TestGRPCPlugin_Contains_Success(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testBypassServer{ok: true})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewBypassClient(conn),
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Contains_Deny(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testBypassServer{ok: false})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewBypassClient(conn),
		log:    xlogger.Nop(),
	}
	assert.False(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Contains_WithService(t *testing.T) {
	srv := &testBypassServer{ok: true}
	conn, cleanup := newTestGRPCConn(t, srv)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewBypassClient(conn),
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1", bypass.WithService("myservice")))
	assert.Equal(t, "myservice", srv.lastService)
}

func TestGRPCPlugin_Contains_WithHostAndPath(t *testing.T) {
	srv := &testBypassServer{ok: true}
	conn, cleanup := newTestGRPCConn(t, srv)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewBypassClient(conn),
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1",
		bypass.WithHostOption("example.com"),
		bypass.WithPathOption("/api/v1"),
	))
	assert.Equal(t, "example.com", srv.lastHost)
	assert.Equal(t, "/api/v1", srv.lastPath)
}

func TestGRPCPlugin_Contains_NilClient(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
	}
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Contains_ServerError(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &errorBypassServer{})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewBypassClient(conn),
		log:    xlogger.Nop(),
	}
	// Server returns an error; Contains should return true (fail-open)
	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Close_NilConn(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
	}
	assert.NoError(t, p.Close())
}

func TestGRPCPlugin_Close_NonCloserConn(t *testing.T) {
	p := &grpcPlugin{
		conn:   &nonCloserConn{},
		client: nil,
	}
	assert.NoError(t, p.Close())
}

func TestGRPCPlugin_Close_WithRealConn(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testBypassServer{ok: true})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: nil,
		log:    xlogger.Nop(),
	}
	assert.NoError(t, p.Close())
}

func TestNewGRPCPlugin_RealConn(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gsrv := grpc.NewServer()
	proto.RegisterBypassServer(gsrv, &testBypassServer{ok: true})
	go gsrv.Serve(lis)
	defer gsrv.Stop()

	p := NewGRPCPlugin("test", lis.Addr().String(), plugin.TimeoutOption(500))
	require.NotNil(t, p)

	assert.True(t, p.Contains(context.Background(), "tcp", "192.168.1.1"))
	assert.NoError(t, p.(io.Closer).Close())
}

func TestGRPCPlugin_IsWhitelist(t *testing.T) {
	p := &grpcPlugin{}
	assert.False(t, p.IsWhitelist())
}

// --- test helpers ---

type testBypassServer struct {
	proto.UnimplementedBypassServer
	ok          bool
	lastService string
	lastHost    string
	lastPath    string
}

func (s *testBypassServer) Bypass(ctx context.Context, req *proto.BypassRequest) (*proto.BypassReply, error) {
	s.lastService = req.Service
	s.lastHost = req.Host
	s.lastPath = req.Path
	return &proto.BypassReply{Ok: s.ok}, nil
}

type errorBypassServer struct {
	proto.UnimplementedBypassServer
}

func (s *errorBypassServer) Bypass(ctx context.Context, req *proto.BypassRequest) (*proto.BypassReply, error) {
	return nil, status.Error(codes.Internal, "internal error")
}

type nonCloserConn struct{}

func (n *nonCloserConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	return nil
}

func (n *nonCloserConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, nil
}

var _ grpc.ClientConnInterface = (*nonCloserConn)(nil)
var _ io.Closer = (*grpcPlugin)(nil)
