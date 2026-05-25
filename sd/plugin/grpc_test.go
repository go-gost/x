package sd

import (
	"context"
	"io"
	"testing"

	"github.com/go-gost/core/sd"
	"github.com/go-gost/plugin/sd/proto"
	"google.golang.org/grpc"
)

// mockSDClient implements proto.SDClient for testing.
type mockSDClient struct {
	registerErr   error
	deregisterErr error
	renewErr      error
	getReply      *proto.GetServiceReply
	getErr        error
}

func (m *mockSDClient) Register(ctx context.Context, in *proto.RegisterRequest, opts ...grpc.CallOption) (*proto.RegisterReply, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return &proto.RegisterReply{Ok: true}, nil
}

func (m *mockSDClient) Deregister(ctx context.Context, in *proto.DeregisterRequest, opts ...grpc.CallOption) (*proto.DeregisterReply, error) {
	if m.deregisterErr != nil {
		return nil, m.deregisterErr
	}
	return &proto.DeregisterReply{Ok: true}, nil
}

func (m *mockSDClient) Renew(ctx context.Context, in *proto.RenewRequest, opts ...grpc.CallOption) (*proto.RenewReply, error) {
	if m.renewErr != nil {
		return nil, m.renewErr
	}
	return &proto.RenewReply{Ok: true}, nil
}

func (m *mockSDClient) Get(ctx context.Context, in *proto.GetServiceRequest, opts ...grpc.CallOption) (*proto.GetServiceReply, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getReply, nil
}

// mockGrpcConn implements grpc.ClientConnInterface and io.Closer.
type mockGrpcConn struct {
	closed bool
}

func (m *mockGrpcConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return nil
}

func (m *mockGrpcConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, nil
}

func (m *mockGrpcConn) Close() error {
	m.closed = true
	return nil
}

// --- NewGRPCPlugin ---

func TestNewGRPCPlugin_ReturnsNonNil(t *testing.T) {
	p := NewGRPCPlugin("test", "127.0.0.1:65535")
	if p == nil {
		t.Fatal("NewGRPCPlugin should never return nil")
	}
}

// --- Register ---

func TestGrpcPlugin_Register_NilClient(t *testing.T) {
	p := &grpcPlugin{}
	if err := p.Register(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Register should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Register_NilService(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	if err := p.Register(context.Background(), nil); err != nil {
		t.Errorf("nil service Register should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Register_Success(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	err := p.Register(context.Background(), &sd.Service{
		ID: "svc-1", Name: "test", Node: "n1", Network: "tcp", Address: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
}

func TestGrpcPlugin_Register_ServerError(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{registerErr: io.ErrUnexpectedEOF}}
	err := p.Register(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Error("Register should return error when server fails")
	}
}

// --- Deregister ---

func TestGrpcPlugin_Deregister_NilClient(t *testing.T) {
	p := &grpcPlugin{}
	if err := p.Deregister(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Deregister should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Deregister_NilService(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	if err := p.Deregister(context.Background(), nil); err != nil {
		t.Errorf("nil service Deregister should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Deregister_Success(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	err := p.Deregister(context.Background(), &sd.Service{
		ID: "svc-1", Name: "test", Node: "n1", Network: "tcp", Address: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}
}

func TestGrpcPlugin_Deregister_ServerError(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{deregisterErr: io.ErrUnexpectedEOF}}
	err := p.Deregister(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Error("Deregister should return error when server fails")
	}
}

// --- Renew ---

func TestGrpcPlugin_Renew_NilClient(t *testing.T) {
	p := &grpcPlugin{}
	if err := p.Renew(context.Background(), &sd.Service{ID: "1"}); err != nil {
		t.Errorf("nil client Renew should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Renew_NilService(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	if err := p.Renew(context.Background(), nil); err != nil {
		t.Errorf("nil service Renew should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Renew_Success(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{}}
	err := p.Renew(context.Background(), &sd.Service{
		ID: "svc-1", Name: "test", Node: "n1", Network: "tcp", Address: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("Renew failed: %v", err)
	}
}

func TestGrpcPlugin_Renew_ServerError(t *testing.T) {
	p := &grpcPlugin{client: &mockSDClient{renewErr: io.ErrUnexpectedEOF}}
	err := p.Renew(context.Background(), &sd.Service{ID: "1"})
	if err == nil {
		t.Error("Renew should return error when server fails")
	}
}

// --- Get ---

func TestGrpcPlugin_Get_NilClient(t *testing.T) {
	p := &grpcPlugin{}
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Errorf("nil client Get should return nil error, got %v", err)
	}
	if services != nil {
		t.Errorf("nil client Get should return nil services, got %v", services)
	}
}

func TestGrpcPlugin_Get_Success(t *testing.T) {
	p := &grpcPlugin{
		client: &mockSDClient{
			getReply: &proto.GetServiceReply{
				Services: []*proto.Service{
					{Id: "1", Name: "test", Node: "n1", Network: "tcp", Address: "10.0.0.1:80"},
					{Id: "2", Name: "test", Node: "n2", Network: "udp", Address: "10.0.0.2:53"},
				},
			},
		},
	}
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0].ID != "1" || services[0].Network != "tcp" {
		t.Errorf("service[0] = %+v, want ID=1 Network=tcp", services[0])
	}
	if services[1].ID != "2" || services[1].Network != "udp" {
		t.Errorf("service[1] = %+v, want ID=2 Network=udp", services[1])
	}
}

func TestGrpcPlugin_Get_SkipsNilServices(t *testing.T) {
	p := &grpcPlugin{
		client: &mockSDClient{
			getReply: &proto.GetServiceReply{
				Services: []*proto.Service{
					{Id: "1", Name: "test"},
					nil,
					{Id: "3", Name: "test"},
				},
			},
		},
	}
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 non-nil services, got %d", len(services))
	}
}

func TestGrpcPlugin_Get_EmptyServices(t *testing.T) {
	p := &grpcPlugin{
		client: &mockSDClient{
			getReply: &proto.GetServiceReply{Services: nil},
		},
	}
	services, err := p.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}
}

func TestGrpcPlugin_Get_ServerError(t *testing.T) {
	p := &grpcPlugin{
		client: &mockSDClient{getErr: io.ErrUnexpectedEOF},
	}
	services, err := p.Get(context.Background(), "test")
	if err == nil {
		t.Error("Get should return error when server fails")
	}
	if services != nil {
		t.Errorf("expected nil services on error, got %v", services)
	}
}

// --- Close ---

func TestGrpcPlugin_Close_NilConn(t *testing.T) {
	p := &grpcPlugin{conn: nil}
	if err := p.Close(); err != nil {
		t.Errorf("Close with nil conn should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Close_WithConn(t *testing.T) {
	conn := &mockGrpcConn{}
	p := &grpcPlugin{conn: conn}
	if err := p.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
	if !conn.closed {
		t.Error("Close should close the underlying connection")
	}
}

func TestGrpcPlugin_Close_ConnWithoutCloser(t *testing.T) {
	// A conn that implements ClientConnInterface but not io.Closer.
	p := &grpcPlugin{conn: &struct{ grpc.ClientConnInterface }{}}
	if err := p.Close(); err != nil {
		t.Errorf("Close on non-io.Closer conn should return nil, got %v", err)
	}
}

// --- Interface assertion ---

var _ sd.SD = (*grpcPlugin)(nil)
