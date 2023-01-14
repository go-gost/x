package relay

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
)

type Connector struct {
	id relay.ConnectorID
	t  time.Time
	s  *mux.Session
}

func NewConnector(id relay.ConnectorID, s *mux.Session) *Connector {
	c := &Connector{
		id: id,
		t:  time.Now(),
		s:  s,
	}
	go c.accept()
	return c
}

func (c *Connector) accept() {
	for {
		conn, err := c.s.Accept()
		if err != nil {
			logger.Default().Errorf("connector %s: %v", c.id, err)
			c.s.Close()
			return
		}
		conn.Close()
	}
}

func (c *Connector) ID() relay.ConnectorID {
	return c.id
}

func (c *Connector) Session() *mux.Session {
	return c.s
}

type Tunnel struct {
	id         relay.TunnelID
	connectors []*Connector
	t          time.Time
	n          uint64
	mu         sync.RWMutex
}

func NewTunnel(id relay.TunnelID) *Tunnel {
	t := &Tunnel{
		id: id,
		t:  time.Now(),
	}
	go t.clean()
	return t
}

func (t *Tunnel) ID() relay.TunnelID {
	return t.id
}

func (t *Tunnel) AddConnector(c *Connector) {
	if c == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.connectors = append(t.connectors, c)
}

func (t *Tunnel) GetConnector() *Connector {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.connectors) == 0 {
		return nil
	}

	n := atomic.AddUint64(&t.n, 1) - 1
	return t.connectors[n%uint64(len(t.connectors))]
}

func (t *Tunnel) clean() {
	ticker := time.NewTicker(3 * time.Second)
	for range ticker.C {
		t.mu.Lock()
		var connectors []*Connector
		for _, c := range t.connectors {
			if c.Session().IsClosed() {
				logger.Default().Debugf("remove tunnel %s connector %s", t.id, c.id)
				continue
			}
			connectors = append(connectors, c)
		}
		if len(connectors) != len(t.connectors) {
			t.connectors = connectors
		}
		t.mu.Unlock()
	}
}

type ConnectorPool struct {
	tunnels map[relay.TunnelID]*Tunnel
	mu      sync.RWMutex
}

func NewConnectorPool() *ConnectorPool {
	return &ConnectorPool{
		tunnels: make(map[relay.TunnelID]*Tunnel),
	}
}

func (p *ConnectorPool) Add(tid relay.TunnelID, c *Connector) {
	p.mu.Lock()
	defer p.mu.Unlock()

	t := p.tunnels[tid]
	if t == nil {
		t = NewTunnel(tid)
		p.tunnels[tid] = t
	}
	t.AddConnector(c)
}

func (p *ConnectorPool) Get(tid relay.TunnelID) *Connector {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	t := p.tunnels[tid]
	if t == nil {
		return nil
	}

	return t.GetConnector()
}
