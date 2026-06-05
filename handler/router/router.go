// Package router implements the "router" handler for the GOST framework.
//
// # Overview
//
// The router handler acts as the ingress point of a VPN-like tunnel mesh. It
// receives relay protocol connections (over TCP) from client-side GOST
// instances, authenticates them, and routes IP packets through the mesh of
// tunnel connectors.
//
// # Data flow
//
//	Client TCP ──► Handle() ──► [auth + relay handshake]
//	                    │
//	                    └──► handleAssociate() ──► packetConn.Read() loop
//	                                  │
//	                                  └──► handlePacket()
//	                                         │
//	                                         ├── 1. Parse IP header (v4/v6)
//	                                         ├── 2. getRoute() to find gateway
//	                                         ├── 3. pool.Get() — forward via connector
//	                                         └── 4. getAddrforRoute() — fallback to
//	                                             epConn.WriteTo() to another node
//
//	External UDP ──► handleEntrypoint() ──► pool.Get() ──► connector.Write()
//
// # Component hierarchy
//
//	ConnectorPool (node-level)
//	  └── Router (per tunnel ID)
//	        └── Connector (per host:port)
//	              └── lockWriter → packetConn → net.Conn (back to client)
//
// # Thread safety
//
// Router and ConnectorPool use sync.RWMutex for all map operations.
// lockWriter serializes writes to the underlying connection, since
// handlePacket and handleEntrypoint may call Write concurrently.
//
// # Connector weighting
//
// Each connector carries a weight embedded in its ConnectorID. When
// multiple connectors exist for the same host, GetConnector uses
// weighted random selection. A weight of MaxWeight (0xff) has special
// meaning: only MaxWeight connectors are selected, providing a
// priority mechanism.
package router

import (
	"io"
	"sync"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"

	"github.com/go-gost/x/selector"
	"github.com/google/uuid"
)

const (
	// MaxWeight is the maximum connector weight. A connector with this
	// weight takes priority over all other connectors for the same host.
	MaxWeight uint8 = 0xff
)

// ConnectorOptions holds optional configuration for a Connector.
// Currently empty but reserved for future use.
type ConnectorOptions struct{}

// Connector represents a single tunnel endpoint bound to a remote client.
//
// A connector is identified by its ConnectorID and associated with a
// TunnelID (router). It pairs a host address with an io.Writer — the
// framed TCP connection back to the client. When the router receives an
// IP packet destined for this connector's host, it writes the raw packet
// to the Writer, and the client-side packetConn decapsulates it.
//
// Lifecycle:
//  1. Created by NewConnector in handleAssociate after the relay handshake.
//  2. Added to the ConnectorPool (and underlying Router) for routing.
//  3. Removed by ConnectorPool.Del when handleAssociate exits (deferred).
//  4. Closed by Router.Close when the router shuts down.
type Connector struct {
	id   relay.ConnectorID
	rid  relay.TunnelID
	host string
	w    io.Writer
	opts *ConnectorOptions
	log  logger.Logger
}

// NewConnector creates a new Connector.
//
// Parameters:
//   - rid:  tunnel/route identifier this connector belongs to
//   - cid:  unique connector identifier (embedding weight)
//   - host: the destination host:port this connector forwards to
//   - w:    the writer for sending IP packets back to the client
//   - opts: optional configuration (nil is replaced with zero value)
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

// ID returns the connector's unique identifier.
func (c *Connector) ID() relay.ConnectorID {
	return c.id
}

// Writer returns the io.Writer for sending data to the remote client.
// Returns nil if the receiver is nil or the writer was not set.
//
// The returned writer is typically a lockWriter wrapping a packetConn
// wrapping the underlying TCP connection — so Write calls are
// automatically framed with a 2-byte length prefix and are
// mutex-protected against concurrent access.
func (c *Connector) Writer() io.Writer {
	if c == nil {
		return nil
	}

	return c.w
}

// Close closes the underlying writer if it implements io.Closer.
// Safe to call on nil receiver or nil writer.
func (c *Connector) Close() error {
	if c == nil || c.w == nil {
		return nil
	}

	if closer, ok := c.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Router manages a set of connectors for a single tunnel (TunnelID).
//
// Connectors are grouped by host address. When a packet arrives destined
// for a particular host, the router selects the appropriate connector
// using weighted random selection.
//
// All methods are safe for concurrent use — the embedded RWMutex guards
// the connectors map.
type Router struct {
	node       string
	id         relay.TunnelID
	connectors map[string][]*Connector // host → ordered list of connectors
	close      chan struct{}           // closed when the router is shut down
	mu         sync.RWMutex
}

// NewRouter creates a new Router identified by node name and tunnel ID.
func NewRouter(node string, rid relay.TunnelID) *Router {
	r := &Router{
		node:       node,
		id:         rid,
		connectors: make(map[string][]*Connector),
		close:      make(chan struct{}),
	}
	return r
}

// ID returns the router's tunnel identifier.
func (r *Router) ID() relay.TunnelID {
	return r.id
}

// AddConnector registers a connector in the router.  Nil connectors are
// silently ignored.
func (r *Router) AddConnector(c *Connector) {
	if c == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.connectors[c.host] = append(r.connectors[c.host], c)
}

// GetConnector selects a connector for the given host using weighted
// random selection.
//
// Selection rules:
//   - Single connector → returned directly.
//   - Multiple connectors → weighted random selection.
//   - A connector with weight == MaxWeight takes priority: only
//     MaxWeight connectors are considered.
//   - Weight 0 is treated as weight 1.
//
// Returns nil if no connector exists for the host.
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

// DelConnector removes a connector identified by its host and connector ID.
// If the removed connector was the last one for the host, the host entry
// is deleted from the map to prevent accumulation of empty slices.
// If no matching connector is found, the call is a no-op.
func (r *Router) DelConnector(host string, cid relay.ConnectorID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	connectors := r.connectors[host]
	for i, c := range connectors {
		if c.id.Equal(cid) {
			connectors = append(connectors[:i], connectors[i+1:]...)
			break
		}
	}

	if len(connectors) == 0 {
		delete(r.connectors, host)
	} else {
		r.connectors[host] = connectors
	}
}

// Close shuts down the router: closes all connectors, clears the map,
// and marks the router as closed.  Subsequent calls are no-ops.
//
// The double-close protection uses a select on r.close — under the
// write lock — so it is race-free.
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

// ConnectorPool manages routers keyed by tunnel ID for a single node.
//
// This is the top-level data structure for connector management. Each
// node has one ConnectorPool, and each pool contains one Router per
// active tunnel.
//
// All methods are nil-safe — calling on a nil *ConnectorPool is valid.
type ConnectorPool struct {
	node    string
	routers map[relay.TunnelID]*Router
	mu      sync.RWMutex
}

// NewConnectorPool creates a new ConnectorPool for the given node.
func NewConnectorPool(node string) *ConnectorPool {
	p := &ConnectorPool{
		node:    node,
		routers: make(map[relay.TunnelID]*Router),
	}

	return p
}

// Add creates or retrieves a Router for the given tunnel ID and adds
// the connector to it.  If no router exists for the tunnel ID, one is
// created automatically.
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

// Get retrieves a connector for the given tunnel ID and host address.
// Returns nil if the pool is nil, the router doesn't exist, or no
// connector matches the host.
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

// Del removes a connector from a specific router.
// Safe to call on a nil pool.
func (p *ConnectorPool) Del(rid relay.TunnelID, host string, cid relay.ConnectorID) {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	r := p.routers[rid]
	if r == nil {
		return
	}

	r.DelConnector(host, cid)
}

// Close shuts down all routers and clears the pool.  Safe to call on a
// nil pool.  Subsequent calls are no-ops (delegates to Router.Close).
func (p *ConnectorPool) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, v := range p.routers {
		v.Close()
	}
	clear(p.routers)

	return nil
}

// parseRouterID converts a UUID string into a relay.TunnelID.
// Returns a zero-value TunnelID if the string is empty or not a valid UUID.
//
// Ingress rules store router identifiers as UUID strings. This function
// bridges the gap between the string form and the binary TunnelID form
// used internally.
func parseRouterID(s string) (rid relay.TunnelID) {
	if s == "" {
		return
	}
	uuid, _ := uuid.Parse(s)

	return relay.NewTunnelID(uuid[:])
}
