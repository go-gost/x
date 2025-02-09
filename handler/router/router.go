package router

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"

	"github.com/go-gost/x/selector"
	"github.com/google/uuid"
)

const (
	MaxWeight uint8 = 0xff
)

type ConnectorOptions struct{}

type Connector struct {
	id   relay.ConnectorID
	rid  relay.TunnelID
	host string
	w    io.Writer
	opts *ConnectorOptions
	log  logger.Logger
}

func NewConnector(rid relay.TunnelID, cid relay.ConnectorID, host string, w io.Writer, opts *ConnectorOptions) *Connector {
	if opts == nil {
		opts = &ConnectorOptions{}
	}

	c := &Connector{
		rid:  rid,
		id:   cid,
		host: host,
		w:    w,
		opts: opts,
		log: logger.Default().WithFields(map[string]any{
			"router":    rid.String(),
			"connector": cid.String(),
			"host":      host,
		}),
	}

	return c
}

func (c *Connector) ID() relay.ConnectorID {
	return c.id
}

func (c *Connector) Writer() io.Writer {
	if c == nil {
		return nil
	}

	return c.w
}

func (c *Connector) Close() error {
	if c == nil || c.w == nil {
		return nil
	}

	if closer, ok := c.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type Router struct {
	node       string
	id         relay.TunnelID
	connectors map[string][]*Connector
	t          time.Time
	close      chan struct{}
	mu         sync.RWMutex
}

func NewRouter(node string, rid relay.TunnelID) *Router {
	r := &Router{
		node:       node,
		id:         rid,
		connectors: make(map[string][]*Connector),
		t:          time.Now(),
		close:      make(chan struct{}),
	}
	return r
}

func (r *Router) ID() relay.TunnelID {
	return r.id
}

func (r *Router) AddConnector(c *Connector) {
	if c == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.connectors[c.host] = append(r.connectors[c.host], c)
}

func (r *Router) GetConnector(host string) *Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connectors := r.connectors[host]

	if len(connectors) == 1 {
		return connectors[0]
	}

	rw := selector.NewRandomWeighted[*Connector]()

	found := false
	for _, c := range connectors {
		weight := c.ID().Weight()
		if weight == 0 {
			weight = 1
		}
		if weight == MaxWeight && !found {
			rw.Reset()
			found = true
		}

		if weight == MaxWeight || !found {
			rw.Add(c, int(weight))
		}
	}

	return rw.Next()
}

func (r *Router) DelConnector(host string, cid relay.ConnectorID) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connectors := r.connectors[host]
	for i, c := range connectors {
		if c.id.Equal(cid) {
			r.connectors[host] = append(connectors[:i], connectors[i+1:]...)
		}
	}
}

func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.close:
	default:
		for _, cs := range r.connectors {
			for _, c := range cs {
				c.Close()
			}
		}
		close(r.close)

		clear(r.connectors)
	}

	return nil
}

type ConnectorPool struct {
	node    string
	routers map[relay.TunnelID]*Router
	mu      sync.RWMutex
	cancel  context.CancelFunc
}

func NewConnectorPool(node string) *ConnectorPool {
	p := &ConnectorPool{
		node:    node,
		routers: make(map[relay.TunnelID]*Router),
	}

	return p
}

func (p *ConnectorPool) Add(rid relay.TunnelID, c *Connector) {
	p.mu.Lock()
	defer p.mu.Unlock()

	r := p.routers[rid]
	if r == nil {
		r = NewRouter(p.node, rid)
		p.routers[rid] = r
	}
	r.AddConnector(c)
}

func (p *ConnectorPool) Get(rid relay.TunnelID, host string) *Connector {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	r := p.routers[rid]
	if r == nil {
		return nil
	}

	return r.GetConnector(host)
}

func (p *ConnectorPool) Del(rid relay.TunnelID, host string, cid relay.ConnectorID) {
	if p == nil {
		return
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	r := p.routers[rid]
	if r == nil {
		return
	}

	r.DelConnector(host, cid)
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

	for _, v := range p.routers {
		v.Close()
	}
	clear(p.routers)

	return nil
}

func parseRouterID(s string) (rid relay.TunnelID) {
	if s == "" {
		return
	}
	uuid, _ := uuid.Parse(s)

	return relay.NewTunnelID(uuid[:])
}
