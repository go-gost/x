package tunnel

import (
	"context"
	"sync"
	"time"

	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/selector"
)

const (
	MaxWeight uint8 = 0xff
)

type Tunnel struct {
	node       string
	id         relay.TunnelID
	connectors []*Connector
	t          time.Time
	close      chan struct{}
	mu         sync.RWMutex
	ttl        time.Duration
}

func NewTunnel(node string, tid relay.TunnelID, ttl time.Duration) *Tunnel {
	t := &Tunnel{
		node:  node,
		id:    tid,
		t:     time.Now(),
		close: make(chan struct{}),
		ttl:   ttl,
	}
	if t.ttl <= 0 {
		t.ttl = defaultTTL
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

	if len(t.connectors) == 1 {
		if t.connectors[0].IsClosed() {
			return nil
		}
		return t.connectors[0]
	}

	rw := selector.NewRandomWeighted[*Connector]()

	found := false
	for _, c := range t.connectors {
		if c.IsClosed() {
			continue
		}

		weight := c.ID().Weight()
		if weight == 0 {
			weight = 1
		}

		if network == "udp" && c.id.IsUDP() ||
			network != "udp" && !c.id.IsUDP() {
			if weight == MaxWeight && !found {
				rw.Reset()
				found = true
			}

			if weight == MaxWeight || !found {
				rw.Add(c, int(weight))
			}
		}
	}

	return rw.Next()
}

func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	select {
	case <-t.close:
	default:
		for _, c := range t.connectors {
			c.Close()
		}
		close(t.close)
	}

	return nil
}

func (t *Tunnel) CloseOnIdle() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

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
	ticker := time.NewTicker(t.ttl)
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
				if c.IsClosed() {
					c.log.Debugf("remove connector: %s %s", t.id, c.id)
					continue
				}

				connectors = append(connectors, c)
				if c.opts.sd != nil {
					c.opts.sd.Renew(context.Background(), &sd.Service{
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
