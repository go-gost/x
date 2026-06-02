package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/sd"
)

// fakePool implements a minimal Connector-like thing for Dialer tests.
type fakePool struct {
	mu   sync.Mutex
	conn net.Conn
}

func (p *fakePool) Get(network, tid string) *Connector {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return nil
	}
	// We return nil to fall through to SD — tested separately
	return nil
}

type fakeSD struct {
	services       []*sd.Service
	err            error
	renewFunc      func(context.Context, *sd.Service) error
	registerFunc   func(ctx context.Context, service *sd.Service) error
	deregisterFunc func(ctx context.Context, service *sd.Service) error
}

func (s *fakeSD) Get(ctx context.Context, name string) ([]*sd.Service, error) {
	return s.services, s.err
}

func (s *fakeSD) Register(ctx context.Context, service *sd.Service, opts ...sd.Option) error {
	if s.registerFunc != nil {
		return s.registerFunc(ctx, service)
	}
	return nil
}

func (s *fakeSD) Deregister(ctx context.Context, service *sd.Service) error {
	if s.deregisterFunc != nil {
		return s.deregisterFunc(ctx, service)
	}
	return nil
}

func (s *fakeSD) Renew(ctx context.Context, service *sd.Service) error {
	if s.renewFunc != nil {
		return s.renewFunc(ctx, service)
	}
	return nil
}

func TestDialer_Dial(t *testing.T) {
	t.Run("nil sd returns ErrTunnelNotAvailable", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		d := &Dialer{
			Node:  "node1",
			Pool:  p,
			Retry: 1,
			Log:   testLogger(),
		}
		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})

	t.Run("sd returns no services", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{services: nil}
		d := &Dialer{
			Node:    "node1",
			Pool:    p,
			SD:      sd,
			Retry:   1,
			Timeout: time.Second,
			Log:     testLogger(),
		}
		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})

	t.Run("sd returns service on different node", func(t *testing.T) {
		// Create a listener so we have a real address to dial
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{
			services: []*sd.Service{
				{
					ID:      "cid1",
					Name:    "testtid",
					Node:    "node2",
					Network: "tcp",
					Address: ln.Addr().String(),
				},
			},
		}
		d := &Dialer{
			Node:    "node1",
			Pool:    p,
			SD:      sd,
			Retry:   1,
			Timeout: time.Second,
			Log:     testLogger(),
		}

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				conn.Close()
			}
		}()

		conn, node, cid, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()
		if node != "node2" {
			t.Errorf("expected node node2, got %s", node)
		}
		if cid != "cid1" {
			t.Errorf("expected cid cid1, got %s", cid)
		}
	})

	t.Run("sd filters out own node", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{
			services: []*sd.Service{
				{
					ID:      "cid1",
					Name:    "testtid",
					Node:    "node1", // same as d.Node — must be filtered
					Network: "tcp",
					Address: "127.0.0.1:9999",
				},
			},
		}
		d := &Dialer{
			Node:    "node1",
			Pool:    p,
			SD:      sd,
			Retry:   1,
			Timeout: time.Second,
			Log:     testLogger(),
		}

		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})

	t.Run("sd filters by network", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{
			services: []*sd.Service{
				{
					ID:      "cid1",
					Name:    "testtid",
					Node:    "node2",
					Network: "udp", // wrong network — must be filtered
					Address: "127.0.0.1:9999",
				},
			},
		}
		d := &Dialer{
			Node:    "node1",
			Pool:    p,
			SD:      sd,
			Retry:   1,
			Timeout: time.Second,
			Log:     testLogger(),
		}

		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})
}

func TestDialer_RetryDefault(t *testing.T) {
	p := NewConnectorPool("node1")
	defer p.Close()
	d := &Dialer{
		Node:  "node1",
		Pool:  p,
		Retry: 0, // should default to 1
		Log:   testLogger(),
	}
	_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
	if err != ErrTunnelNotAvailable {
		t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
	}
}

func TestDialer_SDError(t *testing.T) {
	t.Run("sd.Get returns error", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{err: ErrTunnelNotAvailable}
		d := &Dialer{
			Node:  "node1",
			Pool:  p,
			SD:    sd,
			Retry: 1,
			Log:   testLogger(),
		}
		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})

	t.Run("sd service has empty address", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		sd := &fakeSD{
			services: []*sd.Service{
				{
					ID:      "cid1",
					Name:    "testtid",
					Node:    "node2",
					Network: "tcp",
					Address: "", // empty address
				},
			},
		}
		d := &Dialer{
			Node:  "node1",
			Pool:  p,
			SD:    sd,
			Retry: 1,
			Log:   testLogger(),
		}
		_, _, _, err := d.Dial(context.Background(), "tcp", "testtid")
		if err != ErrTunnelNotAvailable {
			t.Errorf("expected ErrTunnelNotAvailable, got %v", err)
		}
	})
}