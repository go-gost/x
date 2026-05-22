package auth

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	"github.com/go-gost/core/auth"
	corelogger "github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/auth/proto"
	xctx "github.com/go-gost/x/ctx"
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

func newTestGRPCConn(t *testing.T, srv proto.AuthenticatorServer) (*grpc.ClientConn, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gsrv := grpc.NewServer()
	proto.RegisterAuthenticatorServer(gsrv, srv)
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

func TestGRPCPlugin_NilClient(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
		log:    xlogger.Nop(),
	}
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.NoError(t, p.Close())
}

func TestGRPCPlugin_Authenticate_Success(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testAuthServer{ok: true, id: "user1"})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "user1", id)
}

func TestGRPCPlugin_Authenticate_Fail(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testAuthServer{ok: false, id: ""})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestGRPCPlugin_Authenticate_WithService(t *testing.T) {
	server := &testAuthServer{ok: true, id: "srv"}
	conn, cleanup := newTestGRPCConn(t, server)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}
	id, ok := p.Authenticate(context.Background(), "u", "p", auth.WithService("myservice"))
	assert.True(t, ok)
	assert.Equal(t, "srv", id)
	assert.Equal(t, "myservice", server.lastService)
}

func TestGRPCPlugin_Authenticate_WithClientAddr(t *testing.T) {
	server := &testAuthServer{ok: true, id: "addr"}
	conn, cleanup := newTestGRPCConn(t, server)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}

	ctx := context.Background()
	ctx = xctx.ContextWithSrcAddr(ctx, &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234})
	id, ok := p.Authenticate(ctx, "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "addr", id)
	assert.Equal(t, "10.0.0.1:1234", server.lastClient)
}

func TestGRPCPlugin_Authenticate_WithoutClientAddr(t *testing.T) {
	server := &testAuthServer{ok: true, id: "noclient"}
	conn, cleanup := newTestGRPCConn(t, server)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}

	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "noclient", id)
	assert.Empty(t, server.lastClient)
}

func TestGRPCPlugin_Authenticate_ServerError(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &errorAuthServer{})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAuthenticatorClient(conn),
		log:    xlogger.Nop(),
	}
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestNewGRPCPlugin_RealConn(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gsrv := grpc.NewServer()
	proto.RegisterAuthenticatorServer(gsrv, &testAuthServer{ok: true, id: "real"})
	go gsrv.Serve(lis)
	defer gsrv.Stop()

	p := NewGRPCPlugin("test", lis.Addr().String(), plugin.TimeoutOption(500))
	require.NotNil(t, p)

	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.True(t, ok)
	assert.Equal(t, "real", id)
	assert.NoError(t, p.(io.Closer).Close())
}

func TestNewGRPCPlugin_InvalidAddr(t *testing.T) {
	// Null byte causes grpc.NewClient target parsing to fail synchronously.
	// This covers the log.Error(err) path.
	// NOTE: depends on grpc-go's net/url control-character validation.
	// If a future grpc version changes target parsing, this test may silently
	// stop covering the error branch.
	p := NewGRPCPlugin("test", "\x00")
	require.NotNil(t, p)

	// conn is nil, so client is nil, so Authenticate returns false
	id, ok := p.Authenticate(context.Background(), "u", "p")
	assert.False(t, ok)
	assert.Empty(t, id)
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
	conn, cleanup := newTestGRPCConn(t, &testAuthServer{ok: true})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: nil,
		log:    xlogger.Nop(),
	}
	assert.NoError(t, p.Close())
}

// --- test helpers ---

type testAuthServer struct {
	proto.UnimplementedAuthenticatorServer
	ok          bool
	id          string
	lastService string
	lastClient  string
}

func (s *testAuthServer) Authenticate(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateReply, error) {
	s.lastService = req.Service
	s.lastClient = req.Client
	return &proto.AuthenticateReply{Ok: s.ok, Id: s.id}, nil
}

type errorAuthServer struct {
	proto.UnimplementedAuthenticatorServer
}

func (s *errorAuthServer) Authenticate(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateReply, error) {
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
