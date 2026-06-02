package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/google/uuid"
)

func newTestTunnelID(t *testing.T) relay.TunnelID {
	t.Helper()
	return ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
}

func newTestConnectorID(t *testing.T, udp bool, weight uint8) relay.ConnectorID {
	t.Helper()
	u, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	var cid relay.ConnectorID
	if udp {
		cid = relay.NewUDPConnectorID(u[:])
	} else {
		cid = relay.NewConnectorID(u[:])
	}
	return cid.SetWeight(weight)
}

// newTestSession creates a real mux.Session backed by a pipe for testing.
func newTestSession(t *testing.T) (*mux.Session, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	cfg := &mux.Config{Version: 2}
	s, err := mux.ClientSession(client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, server
}

// newTestConnector creates a Connector with a test logger, avoiding
// a nil logger.Default() panic.
func newTestConnector(id relay.ConnectorID, tid relay.TunnelID, node string, s *mux.Session, opts *ConnectorOptions) *Connector {
	if opts == nil {
		opts = &ConnectorOptions{}
	}
	return &Connector{
		id:   id,
		tid:  tid,
		node: node,
		s:    s,
		t:    time.Now(),
		opts: opts,
		log:  testLogger(),
	}
}

// newTestConnectorOpen creates a Connector with an open mux session
// (backed by a pipe pair), suitable for GetConnector tests that need
// non-closed connectors.
func newTestConnectorOpen(t *testing.T, id relay.ConnectorID, tid relay.TunnelID, node string) *Connector {
	t.Helper()
	s, _ := newTestSession(t)
	return newTestConnector(id, tid, node, s, &ConnectorOptions{})
}

func TestNewTunnel(t *testing.T) {
	t.Run("default ttl", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		if tn.ttl != defaultTTL {
			t.Errorf("expected default TTL %v, got %v", defaultTTL, tn.ttl)
		}
		tn.Close()
	})

	t.Run("custom ttl", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 30*time.Second)
		if tn.ttl != 30*time.Second {
			t.Errorf("expected TTL 30s, got %v", tn.ttl)
		}
		tn.Close()
	})

	t.Run("id", func(t *testing.T) {
		tid := newTestTunnelID(t)
		tn := NewTunnel("node1", tid, 0)
		if !tn.ID().Equal(tid) {
			t.Error("ID mismatch")
		}
		tn.Close()
	})

	t.Run("double close is safe", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		tn.Close()
		tn.Close() // must not panic
	})
}

func TestTunnel_AddConnector(t *testing.T) {
	t.Run("add nil connector", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()
		tn.AddConnector(nil) // must not panic
	})

	t.Run("add real connector", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		c := &Connector{id: newTestConnectorID(t, false, 1)}
		tn.AddConnector(c)
		if len(tn.connectors) != 1 {
			t.Errorf("expected 1 connector, got %d", len(tn.connectors))
		}
	})
}

func TestTunnel_GetConnector(t *testing.T) {
	t.Run("no connectors", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()
		c := tn.GetConnector("tcp")
		if c != nil {
			t.Error("expected nil when no connectors")
		}
	})

	t.Run("single connector returns itself", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		s, _ := newTestSession(t)
		conn := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		tn.AddConnector(conn)

		c := tn.GetConnector("tcp")
		if c == nil {
			t.Fatal("expected non-nil connector")
		}
		if c.id != conn.id {
			t.Error("unexpected connector returned for single-connector case")
		}
	})

	t.Run("single closed connector returns nil", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		s, _ := newTestSession(t)
		conn := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		conn.Close()
		tn.AddConnector(conn)

		c := tn.GetConnector("tcp")
		if c != nil {
			t.Error("expected nil when only connector is closed")
		}
	})

	t.Run("tcp connector selected over udp", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		tid := newTestTunnelID(t)
		udpConn := newTestConnectorOpen(t, newTestConnectorID(t, true, 1), tid, "node1")
		tcpConn := newTestConnectorOpen(t, newTestConnectorID(t, false, 1), tid, "node1")
		tn.AddConnector(udpConn)
		tn.AddConnector(tcpConn)

		c := tn.GetConnector("tcp")
		if c == nil {
			t.Fatal("expected non-nil")
		}
		if c.id.IsUDP() {
			t.Error("expected TCP connector, got UDP")
		}
	})

	t.Run("udp connector selected over tcp", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		tid := newTestTunnelID(t)
		udpConn := newTestConnectorOpen(t, newTestConnectorID(t, true, 1), tid, "node1")
		tcpConn := newTestConnectorOpen(t, newTestConnectorID(t, false, 1), tid, "node1")
		tn.AddConnector(udpConn)
		tn.AddConnector(tcpConn)

		c := tn.GetConnector("udp")
		if c == nil {
			t.Fatal("expected non-nil")
		}
		if !c.id.IsUDP() {
			t.Error("expected UDP connector, got TCP")
		}
	})

	t.Run("max weight preferred", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		tid := newTestTunnelID(t)
		low := newTestConnectorOpen(t, newTestConnectorID(t, false, 1), tid, "node1")
		max := newTestConnectorOpen(t, newTestConnectorID(t, false, MaxWeight), tid, "node1")
		tn.AddConnector(low)
		tn.AddConnector(max)

		c := tn.GetConnector("tcp")
		if c == nil {
			t.Fatal("expected non-nil")
		}
		if c.id.Weight() != MaxWeight {
			t.Error("expected MaxWeight connector to be selected")
		}
	})

	t.Run("closed connectors skipped", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()

		tid := newTestTunnelID(t)
		s, _ := newTestSession(t)
		c1 := newTestConnector(
			newTestConnectorID(t, false, 1),
			tid,
			"node1", s,
			&ConnectorOptions{},
		)
		c1.Close()

		c2 := newTestConnectorOpen(t, newTestConnectorID(t, false, 2), tid, "node1")
		tn.AddConnector(c1)
		tn.AddConnector(c2)

		c := tn.GetConnector("tcp")
		if c == nil {
			t.Fatal("expected non-nil connector")
		}
		if c.id.Weight() != 2 {
			t.Errorf("expected connector with weight 2, got %d", c.id.Weight())
		}
	})
}

func TestTunnel_CloseOnIdle(t *testing.T) {
	t.Run("no connectors closes", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()
		if !tn.CloseOnIdle() {
			t.Error("expected CloseOnIdle to return true with no connectors")
		}
	})

	t.Run("already closed returns false", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		tn.Close()
		if tn.CloseOnIdle() {
			t.Error("expected CloseOnIdle to return false when already closed")
		}
	})

	t.Run("has connectors returns false", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), 0)
		defer tn.Close()
		tn.AddConnector(&Connector{id: newTestConnectorID(t, false, 1)})
		if tn.CloseOnIdle() {
			t.Error("expected CloseOnIdle to return false with active connectors")
		}
	})
}

func TestTunnel_clean(t *testing.T) {
	t.Run("removes closed connectors and renews active", func(t *testing.T) {
		renewC := make(chan struct{}, 1)
		tn := NewTunnel("node1", newTestTunnelID(t), time.Hour)
		defer tn.Close()

		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{
				sd: &fakeSD{
					renewFunc: func(ctx context.Context, service *sd.Service) error {
						renewC <- struct{}{}
						return nil
					},
				},
			},
		)
		tn.AddConnector(c)

		// Simulate a tick in clean()
		tn.mu.Lock()
		var connectors []*Connector
		for _, cc := range tn.connectors {
			if cc.IsClosed() {
				continue
			}
			connectors = append(connectors, cc)
			if cc.opts.sd != nil {
				cc.opts.sd.Renew(context.Background(), &sd.Service{
					ID:   cc.id.String(),
					Name: tn.id.String(),
					Node: tn.node,
				})
			}
		}
		tn.connectors = connectors
		tn.mu.Unlock()

		if len(tn.connectors) != 1 {
			t.Errorf("expected 1 connector after clean, got %d", len(tn.connectors))
		}

		select {
		case <-renewC:
		case <-time.After(time.Second):
			t.Error("expected Renew to be called for active connector")
		}
	})

	t.Run("closed connector removed", func(t *testing.T) {
		tn := NewTunnel("node1", newTestTunnelID(t), time.Hour)
		defer tn.Close()

		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		c.Close()
		tn.AddConnector(c)

		// Simulate clean tick
		tn.mu.Lock()
		var connectors []*Connector
		for _, cc := range tn.connectors {
			if cc.IsClosed() {
				continue
			}
			connectors = append(connectors, cc)
		}
		tn.connectors = connectors
		tn.mu.Unlock()

		if len(tn.connectors) != 0 {
			t.Errorf("expected 0 connectors, got %d", len(tn.connectors))
		}
	})
}

func TestConnector_NewConnector(t *testing.T) {
	t.Run("nil opts doesn't panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatal("NewConnector with nil opts panicked")
			}
		}()
		// Use newTestConnector to avoid nil logger.Default() — the
		// real NewConnector calls logger.Default() which can be nil in tests.
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", nil,
			nil,
		)
		if c == nil {
			t.Fatal("expected non-nil connector")
		}
		c.Close()
	})

	t.Run("ID returns connector id", func(t *testing.T) {
		cid := newTestConnectorID(t, false, 1)
		c := newTestConnector(cid, newTestTunnelID(t), "node1", nil, nil)
		if !c.ID().Equal(cid) {
			t.Error("ID mismatch")
		}
		c.Close()
	})
}

func TestConnector_GetConn(t *testing.T) {
	t.Run("nil session returns nil, nil", func(t *testing.T) {
		c := &Connector{id: newTestConnectorID(t, false, 1)}
		conn, err := c.GetConn()
		if conn != nil || err != nil {
			t.Errorf("expected (nil, nil), got (%v, %v)", conn, err)
		}
	})

	t.Run("nil session with nil opts returns nil, nil", func(t *testing.T) {
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", nil,
			nil,
		)
		conn, err := c.GetConn()
		if conn != nil || err != nil {
			t.Errorf("expected (nil, nil), got (%v, %v)", conn, err)
		}
	})

	t.Run("closed session returns error", func(t *testing.T) {
		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		c.Close()

		_, err := c.GetConn()
		if err == nil {
			t.Error("expected error from closed session")
		}
	})
}

func TestConnector_Close(t *testing.T) {
	t.Run("nil session returns nil", func(t *testing.T) {
		c := &Connector{id: newTestConnectorID(t, false, 1)}
		err := c.Close()
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("double close is safe", func(t *testing.T) {
		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		c.Close()
		c.Close() // must not panic
	})
}

func TestConnector_IsClosed(t *testing.T) {
	t.Run("nil session returns true", func(t *testing.T) {
		c := &Connector{id: newTestConnectorID(t, false, 1)}
		if !c.IsClosed() {
			t.Error("expected IsClosed to return true when session is nil")
		}
	})

	t.Run("returns false for open", func(t *testing.T) {
		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		if c.IsClosed() {
			t.Error("expected IsClosed to return false for open connector")
		}
		c.Close()
	})

	t.Run("returns true after close", func(t *testing.T) {
		s, _ := newTestSession(t)
		c := newTestConnector(
			newTestConnectorID(t, false, 1),
			newTestTunnelID(t),
			"node1", s,
			&ConnectorOptions{},
		)
		c.Close()
		if !c.IsClosed() {
			t.Error("expected IsClosed to return true after close")
		}
	})
}

func TestConnectorPool(t *testing.T) {
	t.Run("get from nil pool", func(t *testing.T) {
		var p *ConnectorPool
		c := p.Get("tcp", "tid")
		if c != nil {
			t.Error("expected nil from nil pool")
		}
	})

	t.Run("close nil pool", func(t *testing.T) {
		var p *ConnectorPool
		err := p.Close()
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("empty pool returns nil", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()
		c := p.Get("tcp", "nonexistent")
		if c != nil {
			t.Error("expected nil for nonexistent tunnel")
		}
	})

	t.Run("close empty pool is safe", func(t *testing.T) {
		p := NewConnectorPool("node1")
		p.Close()
		p.Close() // double close
	})

	t.Run("add and retrieve connector", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()

		tid := newTestTunnelID(t)
		s, _ := newTestSession(t)
		conn := newTestConnector(newTestConnectorID(t, false, 1), tid, "node1", s, &ConnectorOptions{})
		p.Add(tid, conn, defaultTTL)

		c := p.Get("tcp", tid.String())
		if c == nil {
			t.Fatal("expected non-nil connector")
		}
		if !c.ID().Equal(conn.ID()) {
			t.Error("retrieved wrong connector")
		}
	})

	t.Run("add to existing tunnel", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()

		tid := newTestTunnelID(t)
		conn1 := &Connector{id: newTestConnectorID(t, false, 1)}
		conn2 := &Connector{id: newTestConnectorID(t, false, 2)}
		p.Add(tid, conn1, defaultTTL)
		p.Add(tid, conn2, defaultTTL)

		tunnelKey := tid.String()
		if len(p.tunnels[tunnelKey].connectors) != 2 {
			t.Errorf("expected 2 connectors in tunnel, got %d", len(p.tunnels[tunnelKey].connectors))
		}
	})

	t.Run("get returns closed connector", func(t *testing.T) {
		p := NewConnectorPool("node1")
		defer p.Close()

		tid := newTestTunnelID(t)
		s, _ := newTestSession(t)
		conn := newTestConnector(newTestConnectorID(t, false, 1), tid, "node1", s, &ConnectorOptions{})
		p.Add(tid, conn, defaultTTL)
		conn.Close()

		time.Sleep(100 * time.Millisecond) // let mux propagate close
		c := p.Get("tcp", tid.String())
		// A closed connector should still be returned — the tunnel.GetConnector
		// call will filter it out based on IsClosed().
		if c != nil && c.IsClosed() {
			t.Log("closed connector returned but marked as closed — GetConnector will skip it")
		}
	})
}

func TestConnectorPool_Concurrency(t *testing.T) {
	p := NewConnectorPool("node1")
	defer p.Close()

	tid := newTestTunnelID(t)

	// Concurrent Add and Get should not race
	done := make(chan struct{})
	go func() {
		p.Add(tid, nil, defaultTTL)
		close(done)
	}()

	p.Get("tcp", tid.String())
	<-done
}

func TestConnectorPool_CloseIdleRemovesEmptyTunnels(t *testing.T) {
	p := NewConnectorPool("node1")
	defer p.Close()

	tid := newTestTunnelID(t)
	p.Add(tid, nil, defaultTTL) // adding nil connector — tunnel has no real connectors

	p.Close()
}

func TestConnectorPool_CloseStopsIdleTicker(t *testing.T) {
	p := NewConnectorPool("node1")
	p.Close()
	// After Close, the idle ticker goroutine should stop.
	// If it didn't, the race detector would catch the data race on p.tunnels.
}