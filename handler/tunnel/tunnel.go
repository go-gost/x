package tunnel

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/google/uuid"
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
	node       string
	id         relay.TunnelID
	connectors []*Connector
	t          time.Time
	n          uint64
	close      chan struct{}
	mu         sync.RWMutex
	sd         sd.SD
}

func NewTunnel(node string, tid relay.TunnelID) *Tunnel {
	t := &Tunnel{
		node:  node,
		id:    tid,
		t:     time.Now(),
		close: make(chan struct{}),
	}
	go t.clean()
	return t
}

func (t *Tunnel) WithSD(sd sd.SD) {
	t.sd = sd
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

func (t *Tunnel) GetConnector(network string) *Connector {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var connectors []*Connector
	for _, c := range t.connectors {
		if c.Session().IsClosed() {
			continue
		}
		if network == "udp" && c.id.IsUDP() ||
			network != "udp" && !c.id.IsUDP() {
			connectors = append(connectors, c)
		}
	}
	if len(connectors) == 0 {
		return nil
	}
	n := atomic.AddUint64(&t.n, 1) - 1
	return connectors[n%uint64(len(connectors))]
}

func (t *Tunnel) CloseOnIdle() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	select {
	case <-t.close:
	default:
		if len(t.connectors) == 0 {
			close(t.close)
			return true
		}
	}
	return false
}

func (t *Tunnel) clean() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			if len(t.connectors) == 0 {
				t.mu.Unlock()
				break
			}
			var connectors []*Connector
			for _, c := range t.connectors {
				if c.Session().IsClosed() {
					logger.Default().Debugf("remove tunnel: %s, connector: %s", t.id, c.id)
					if t.sd != nil {
						t.sd.Deregister(context.Background(), &sd.Service{
							ID:   c.id.String(),
							Name: t.id.String(),
							Node: t.node,
						})
					}
					continue
				}

				connectors = append(connectors, c)
				if t.sd != nil {
					t.sd.Renew(context.Background(), &sd.Service{
						ID:   c.id.String(),
						Name: t.id.String(),
						Node: t.node,
					})
				}
			}
			if len(connectors) != len(t.connectors) {
				t.connectors = connectors
			}
			t.mu.Unlock()
		case <-t.close:
			return
		}
	}
}

type ConnectorPool struct {
	node    string
	sd      sd.SD
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

func NewConnectorPool(node string, sd sd.SD) *ConnectorPool {
	p := &ConnectorPool{
		node:    node,
		sd:      sd,
		tunnels: make(map[string]*Tunnel),
	}
	go p.closeIdles()
	return p
}

func (p *ConnectorPool) Add(tid relay.TunnelID, c *Connector) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := tid.String()

	t := p.tunnels[s]
	if t == nil {
		t = NewTunnel(p.node, tid)
		t.WithSD(p.sd)

		p.tunnels[s] = t
	}
	t.AddConnector(c)
}

func (p *ConnectorPool) Get(network string, tid string) *Connector {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	t := p.tunnels[tid]
	if t == nil {
		return nil
	}

	return t.GetConnector(network)
}

func (p *ConnectorPool) closeIdles() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for k, v := range p.tunnels {
			if v.CloseOnIdle() {
				delete(p.tunnels, k)
				logger.Default().Debugf("remove idle tunnel: %s", k)
			}
		}
		p.mu.Unlock()
	}
}

func parseTunnelID(s string) (tid relay.TunnelID) {
	if s == "" {
		return
	}
	private := false
	if s[0] == '$' {
		private = true
		s = s[1:]
	}
	uuid, _ := uuid.Parse(s)

	if private {
		return relay.NewPrivateTunnelID(uuid[:])
	}
	return relay.NewTunnelID(uuid[:])
}
