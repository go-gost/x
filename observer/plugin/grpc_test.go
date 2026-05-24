package observer

import (
	"context"
	"io"
	"os"
	"testing"

	corelogger "github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/plugin/observer/proto"
	xlogger "github.com/go-gost/x/logger"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/service"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	corelogger.SetDefault(xlogger.Nop())
	os.Exit(m.Run())
}

// mockGrpcClient implements proto.ObserverClient for testing.
type mockGrpcClient struct {
	observeReply *proto.ObserveReply
	observeErr   error
}

func (m *mockGrpcClient) Observe(ctx context.Context, in *proto.ObserveRequest, opts ...grpc.CallOption) (*proto.ObserveReply, error) {
	if m.observeErr != nil {
		return nil, m.observeErr
	}
	return m.observeReply, nil
}

type mockGrpcConn struct {
	closed bool
}

func (m *mockGrpcConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	return nil
}

func (m *mockGrpcConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, nil
}

func (m *mockGrpcConn) Close() error {
	m.closed = true
	return nil
}

func TestNewGRPCPlugin_ReturnsNonNil(t *testing.T) {
	// NewGRPCPlugin should always return a non-nil observer. Even if the
	// underlying gRPC dial would eventually fail, modern gRPC uses lazy
	// connect so the constructor always returns a valid instance.
	p := NewGRPCPlugin("test", "127.0.0.1:65535")
	if p == nil {
		t.Fatal("NewGRPCPlugin should never return nil")
	}
}

func TestGrpcPlugin_Observe_NoOpClient_DoesNotPanic(t *testing.T) {
	// When client is nil (e.g., from connection error or deliberate no-op),
	// Observe should return nil without panicking.
	p := &grpcPlugin{client: nil}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err != nil {
		t.Errorf("no-op observer should return nil on Observe, got %v", err)
	}
}

func TestGrpcPlugin_Observe_NilClient(t *testing.T) {
	p := &grpcPlugin{
		conn:   nil,
		client: nil,
	}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err != nil {
		t.Errorf("nil client Observe should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Observe_EmptyEvents(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{},
	}
	// Empty events should return nil without calling the client
	err := p.Observe(context.Background(), nil)
	if err != nil {
		t.Errorf("empty events should return nil, got %v", err)
	}
}

func TestGrpcPlugin_Observe_StatusEvent(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{
			observeReply: &proto.ObserveReply{Ok: true},
		},
	}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{
			Kind:    "service",
			Service: "test-svc",
			State:   "running",
			Msg:     "started",
		},
	})
	if err != nil {
		t.Errorf("Observe with status event failed: %v", err)
	}
}

func TestGrpcPlugin_Observe_StatsEvent(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{
			observeReply: &proto.ObserveReply{Ok: true},
		},
	}
	err := p.Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{
			Kind:         "service",
			Service:      "test-svc",
			Client:       "client1",
			TotalConns:   10,
			CurrentConns: 3,
			InputBytes:   1024,
			OutputBytes:  2048,
			TotalErrs:    1,
		},
	})
	if err != nil {
		t.Errorf("Observe with stats event failed: %v", err)
	}
}

func TestGrpcPlugin_Observe_ServerError(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{
			observeErr: io.ErrUnexpectedEOF,
		},
		log: xlogger.Nop(),
	}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error when server fails")
	}
}

func TestGrpcPlugin_Observe_ReplyNotOk(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{
			observeReply: &proto.ObserveReply{Ok: false},
		},
	}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error when reply is not ok")
	}
}

func TestGrpcPlugin_Observe_NilReply(t *testing.T) {
	p := &grpcPlugin{
		client: &mockGrpcClient{
			observeReply: nil,
		},
	}
	err := p.Observe(context.Background(), []observer.Event{
		service.ServiceEvent{Kind: "service", Service: "test"},
	})
	if err == nil {
		t.Error("Observe should return error when reply is nil")
	}
}

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

// Test that grpcPlugin satisfies observer.Observer
var _ observer.Observer = (*grpcPlugin)(nil)
