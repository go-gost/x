package relay

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
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

func (t *Tunnel) GetConnector(network string) *Connector {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var connectors []*Connector
	for _, c := range t.connectors {
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
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

func NewConnectorPool() *ConnectorPool {
	return &ConnectorPool{
		tunnels: make(map[string]*Tunnel),
	}
}

func (p *ConnectorPool) Add(tid relay.TunnelID, c *Connector) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := tid.String()

	t := p.tunnels[s]
	if t == nil {
		t = NewTunnel(tid)
		p.tunnels[s] = t
	}
	t.AddConnector(c)
}

func (p *ConnectorPool) Get(network string, tid relay.TunnelID) *Connector {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	t := p.tunnels[tid.String()]
	if t == nil {
		return nil
	}

	return t.GetConnector(network)
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

func getTunnelConn(network string, pool *ConnectorPool, tid relay.TunnelID, retry int, log logger.Logger) (conn net.Conn, cid relay.ConnectorID, err error) {
	if retry <= 0 {
		retry = 1
	}
	for i := 0; i < retry; i++ {
		c := pool.Get(network, tid)
		if c == nil {
			err = fmt.Errorf("tunnel %s not available", tid.String())
			break
		}

		conn, err = c.Session().GetConn()
		if err != nil {
			log.Error(err)
			continue
		}
		cid = c.id
		break
	}

	return
}
