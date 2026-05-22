package admission

import (
	"context"
	"io"
	"net"
	"os"
	"testing"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/plugin/admission/proto"
	"github.com/go-gost/x/internal/plugin"
	xlogger "github.com/go-gost/x/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	corelogger "github.com/go-gost/core/logger"
)

func TestMain(m *testing.M) {
	corelogger.SetDefault(xlogger.Nop())
	os.Exit(m.Run())
}

// helper to set up a real gRPC server on a random port, returning the client conn and server stop func.
func newTestGRPCConn(t *testing.T, srv proto.AdmissionServer) (*grpc.ClientConn, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gsrv := grpc.NewServer()
	proto.RegisterAdmissionServer(gsrv, srv)
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

func TestGRPCPlugin_FailOpen(t *testing.T) {
	// Test fail-open: create directly with nil client to ensure nil path is covered.
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
	assert.NoError(t, p.Close())
}

func TestGRPCPlugin_Admit_Success(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testAdmissionServer{admit: true})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAdmissionClient(conn),
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Admit_Deny(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &testAdmissionServer{admit: false})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAdmissionClient(conn),
		log:    xlogger.Nop(),
	}
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

func TestGRPCPlugin_Admit_WithService(t *testing.T) {
	server := &testAdmissionServer{admit: true}
	conn, cleanup := newTestGRPCConn(t, server)
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAdmissionClient(conn),
		log:    xlogger.Nop(),
	}
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1", admission.WithService("myservice")))
	assert.Equal(t, "myservice", server.lastService)
}

func TestGRPCPlugin_Admit_NilClient(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
	}
	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
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
	conn, cleanup := newTestGRPCConn(t, &testAdmissionServer{admit: true})
	defer cleanup()

	// conn is *grpc.ClientConn which implements io.Closer
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
	proto.RegisterAdmissionServer(gsrv, &testAdmissionServer{admit: true})
	go gsrv.Serve(lis)
	defer gsrv.Stop()

	// Call the real NewGRPCPlugin function.
	p := NewGRPCPlugin("test", lis.Addr().String(), plugin.TimeoutOption(500))
	require.NotNil(t, p)

	assert.True(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
	assert.NoError(t, p.(io.Closer).Close())
}

func TestGRPCPlugin_Admit_ServerError(t *testing.T) {
	conn, cleanup := newTestGRPCConn(t, &errorAdmissionServer{})
	defer cleanup()

	p := &grpcPlugin{
		conn:   conn,
		client: proto.NewAdmissionClient(conn),
		log:    xlogger.Nop(),
	}
	// Server returns an error; Admit should return false.
	assert.False(t, p.Admit(context.Background(), "tcp", "192.168.1.1"))
}

// --- test helpers ---

type testAdmissionServer struct {
	proto.UnimplementedAdmissionServer
	admit       bool
	lastService string
}

func (s *testAdmissionServer) Admit(ctx context.Context, req *proto.AdmissionRequest) (*proto.AdmissionReply, error) {
	s.lastService = req.Service
	return &proto.AdmissionReply{Ok: s.admit}, nil
}

type errorAdmissionServer struct {
	proto.UnimplementedAdmissionServer
}

func (s *errorAdmissionServer) Admit(ctx context.Context, req *proto.AdmissionRequest) (*proto.AdmissionReply, error) {
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
