package tunnel

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"

	"github.com/go-gost/core/observer/stats"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
)

type ConnectorOptions struct {
	service string
	sd      sd.SD
	stats   stats.Stats
	limiter traffic.TrafficLimiter
}

// Connector represents one mux-session tunnel endpoint registered by an
// internal client via CmdBind.
//
// Each Connector wraps a smux.Session created by mux.ClientSession. From the
// server side, Connector.GetConn() calls OpenStream() to create a stream to
// the internal client.
//
// Connector.waitClose is a background goroutine that accepts and discards
// unexpected inbound streams. This is a safety guard: the Connector's mux
// session is supposed to be used unidirectionally (server→client), and any
// stream arriving from the client side is anomalous and is safely discarded.
// Normal request streams are created by the server side via OpenStream and
// consumed by the internal client's Accept loop — they never pass through
// waitClose.
//
// When the mux session is closed (client disconnect or network error),
// waitClose detects the Accept error, closes the Connector, and deregisters
// from SD if configured.
type Connector struct {
	id   relay.ConnectorID
	tid  relay.TunnelID
	node string
	s    *mux.Session
	t    time.Time
	opts *ConnectorOptions
	log  logger.Logger
}

func NewConnector(id relay.ConnectorID, tid relay.TunnelID, node string, s *mux.Session, opts *ConnectorOptions) *Connector {
	if opts == nil {
		opts = &ConnectorOptions{}
	}

	c := &Connector{
		id:   id,
		tid:  tid,
		node: node,
		s:    s,
		t:    time.Now(),
		opts: opts,
		log: logger.Default().WithFields(map[string]any{
			"node":      node,
			"tunnel":    tid.String(),
			"connector": id.String(),
		}),
	}

	go c.waitClose()
	return c
}

func (c *Connector) waitClose() {
	for {
		conn, err := c.s.Accept()
		if err != nil {
			c.log.Errorf("connector %s: %v", c.id, err)
			c.Close()
			if c.opts.sd != nil {
				c.opts.sd.Deregister(context.Background(), &sd.Service{
					ID:   c.id.String(),
					Name: c.tid.String(),
					Node: c.node,
				})
				c.log.Debugf("deregister connector %s from sd", c.id.String())
			}
			return
		}
		conn.Close()
	}
}

func (c *Connector) ID() relay.ConnectorID {
	return c.id
}

func (c *Connector) GetConn() (net.Conn, error) {
	if c == nil || c.s == nil {
		return nil, nil
	}

	conn, err := c.s.GetConn()
	if err != nil {
		return nil, err
	}

	conn = stats_wrapper.WrapConn(conn, c.opts.stats)

	network := "tcp"
	if c.id.IsUDP() {
		network = "udp"
	}
	conn = traffic_wrapper.WrapConn(
		conn,
		c.opts.limiter,
		c.tid.String(),
		limiter.ScopeOption(limiter.ScopeClient),
		limiter.ServiceOption(c.opts.service),
		limiter.ClientOption(c.tid.String()),
		limiter.NetworkOption(network),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)
	return conn, nil
}

func (c *Connector) Close() error {
	if c == nil || c.s == nil {
		return nil
	}

	return c.s.Close()
}

func (c *Connector) IsClosed() bool {
	if c == nil || c.s == nil {
		return true
	}

	return c.s.IsClosed()
}

// ConnectorPool manages all Tunnel objects for this tunnel handler node.
//
// Hierarchy:
//
//	ConnectorPool (per node) → map[tunnelID]*Tunnel → []*Connector
//	                                                    └── *mux.Session
//
// Each Tunnel holds Connectors sharing the same tunnel ID. Tunnels that have
// no active connectors for 15 minutes are removed by closeIdles.
//
// Methods: Add (insert connector, creating Tunnel on demand), Get (select best
// connector by network type), Close (stop idle ticker, remove all tunnels).
type ConnectorPool struct {
	node    string
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
	cancel  context.CancelFunc
}

func NewConnectorPool(node string) *ConnectorPool {
	ctx, cancel := context.WithCancel(context.Background())

	p := &ConnectorPool{
		node:    node,
		tunnels: make(map[string]*Tunnel),
		cancel:  cancel,
	}

	go p.closeIdles(ctx)
	return p
}

func (p *ConnectorPool) Add(tid relay.TunnelID, c *Connector, ttl time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := tid.String()

	t := p.tunnels[s]
	if t == nil {
		t = NewTunnel(p.node, tid, ttl)
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

func (p *ConnectorPool) Close() error {
	if p == nil {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for k, v := range p.tunnels {
		v.Close()
		delete(p.tunnels, k)
	}

	return nil
}

func (p *ConnectorPool) closeIdles(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			for k, v := range p.tunnels {
				if v.CloseOnIdle() {
					delete(p.tunnels, k)
					logger.Default().Debugf("remove idle tunnel: %s", k)
				}
			}
			p.mu.Unlock()

		case <-ctx.Done():
			return
		}
	}
}