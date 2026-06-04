package router

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	xip "github.com/go-gost/x/internal/net/ip"
	"github.com/go-gost/x/internal/util/cache"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/google/uuid"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// handleAssociate establishes a tunnel association for IP packet forwarding.
//
// This is the core of the router handler. Once the relay handshake
// completes, the TCP connection enters a long-lived "associate" state:
// the client sends IP packets (framed by packetConn) and the router
// forwards them through the mesh.
//
// # Sequence
//
//  1. Check ingress rules: does this host belong to this router?
//  2. Generate a unique connector ID.
//  3. Send the success response (with connector ID) to the client.
//  4. Wrap the TCP conn as packetConn for framed reads.
//  5. Apply stats and traffic limiter wrappers.
//  6. Register the connector in the pool.
//  7. Register with service discovery (if configured).
//  8. Enter the read loop: read framed packet → handlePacket.
//
// # Cleanup
//
// The connector is automatically removed from the pool (via defer)
// and deregistered from service discovery when this function returns.
//
// The TCP connection is NOT closed here — the caller (Handle) defers
// conn.Close(), so when handleAssociate returns (on any error), the
// connection is cleaned up.
func (h *routerHandler) handleAssociate(ctx context.Context, conn net.Conn, network, host string, routerID relay.TunnelID, log logger.Logger) (err error) {
	log = log.WithFields(map[string]any{
		"dst":    fmt.Sprintf("%s/%s", host, network),
		"cmd":    "associate",
		"router": routerID.String(),
		"host":   host,
	})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	// ---- Step 1: Ingress check ----
	// If an ingress controller is configured, verify that this router is
	// the designated router for the requested host. This prevents clients
	// from connecting to the wrong router.
	if ing := h.md.ingress; ing != nil && host != "" {
		var rid relay.TunnelID
		if rule := ing.GetRule(ctx, host, ingress.WithService(h.options.Service)); rule != nil {
			rid = parseRouterID(rule.Endpoint)
		}

		if !rid.Equal(routerID) {
			resp.Status = relay.StatusHostUnreachable
			if _, werr := resp.WriteTo(conn); werr != nil {
				log.Error(werr)
			}
			err := fmt.Errorf("no route to host %s", host)
			log.Error(err)
			return err
		}
	}

	// ---- Step 2: Generate connector ID ----
	uuid, err := uuid.NewRandom()
	if err != nil {
		resp.Status = relay.StatusInternalServerError
		if _, werr := resp.WriteTo(conn); werr != nil {
			log.Error(werr)
		}
		return
	}
	connectorID := relay.NewConnectorID(uuid[:])

	// ---- Step 3: Send success response ----
	// The connector ID is sent back to the client so it can identify
	// itself in subsequent communications.
	resp.Features = append(resp.Features,
		&relay.TunnelFeature{
			ID: connectorID,
		},
	)
	if _, werr := resp.WriteTo(conn); werr != nil {
		log.Error(werr)
	}

	// ---- Step 4: Wrap connection for framed reads ----
	// packetConn adds a 2-byte big-endian length prefix to each IP
	// packet read from the TCP stream, so individual packets can be
	// delineated despite TCP's stream nature.
	conn = &packetConn{conn}

	// ---- Step 5: Apply stats and traffic limiting wrappers ----
	clientID := fmt.Sprintf("%s@%s", host, routerID)
	var stats stats.Stats
	if h.stats != nil {
		stats = h.stats.Stats(clientID)
	}
	conn = stats_wrapper.WrapConn(conn, stats)
	conn = traffic_wrapper.WrapConn(
		conn,
		h.limiter,
		clientID,
		limiter.ScopeOption(limiter.ScopeClient),
		limiter.ServiceOption(h.options.Service),
		limiter.ClientOption(clientID),
		limiter.NetworkOption(network),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)

	// ---- Step 6: Register connector ----
	// The connector's Writer uses LockWriter to serialize concurrent
	// writes from handlePacket and handleEntrypoint.
	h.pool.Add(routerID, NewConnector(routerID, connectorID, host, LockWriter(conn), &ConnectorOptions{}))
	defer h.pool.Del(routerID, host, connectorID)

	// ---- Step 7: Service discovery registration ----
	// Register the new connector so other mesh nodes can discover it
	// and forward packets to it via the entrypoint.
	if h.md.sd != nil {
		err := h.md.sd.Register(ctx, &sd.Service{
			ID:      connectorID.String(),
			Name:    clientID,
			Node:    h.id,
			Network: "udp",
			Address: h.md.entryPoint,
		})
		if err != nil {
			h.log.Error(err)
		}

		defer h.md.sd.Deregister(ctx, &sd.Service{
			ID:   connectorID.String(),
			Name: clientID,
			Node: h.id,
		})

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		go h.sdRenew(ctx, clientID, connectorID.String())
	}

	log.Debugf("%s/%s: router=%s, connector=%s, weight=%d established", host, network, routerID, connectorID, connectorID.Weight())

	// ---- Step 8: Read loop ----
	// Each iteration reads one framed IP packet and routes it through
	// the mesh. The loop exits when the client disconnects (EOF) or
	// a read error occurs.
	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	for {
		n, err := conn.Read(b)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		h.handlePacket(ctx, b[:n], routerID, log)
	}
}

// sdRenew periodically renews the service discovery registration for a
// connector. This keeps the connector's address alive in the SD backend
// so other nodes can discover it.
//
// The renewal interval is controlled by metadata.sdRenewInterval
// (default: 15s). The goroutine exits when the context is cancelled.
func (h *routerHandler) sdRenew(ctx context.Context, clientID string, connectorID string) {
	tc := time.NewTicker(h.md.sdRenewInterval)
	defer tc.Stop()

	for {
		select {
		case <-tc.C:
			h.md.sd.Renew(ctx, &sd.Service{
				ID:   connectorID,
				Name: clientID,
				Node: h.id,
			})
		case <-ctx.Done():
			return
		}
	}
}

// handlePacket processes a single IP packet and forwards it toward its
// destination through the tunnel mesh.
//
// # Routing algorithm
//
//  1. Parse the IP header (IPv4 or IPv6) to extract the destination IP.
//  2. Look up a route for the destination IP via getRoute().
//  3. If a connector exists for the route's gateway, write the packet
//     directly to that connector → it goes to the client that owns the
//     destination subnet.
//  4. If no local connector exists, use getAddrforRoute() to find a
//     remote node via service discovery, then forward the packet via
//     epConn.WriteTo() (UDP to the remote node's entrypoint).
//  5. If no route or no peer address is found, the packet is silently
//     dropped (logged as an error).
//
// The packet is forwarded as-is (raw IP), wrapped in a relay request
// when sent via the entrypoint.
func (h *routerHandler) handlePacket(ctx context.Context, data []byte, routerID relay.TunnelID, log logger.Logger) error {
	// ---- Parse IP header ----
	var dstIP net.IP
	if waterutil.IsIPv4(data) {
		header, err := ipv4.ParseHeader(data)
		if err != nil {
			return err
		}

		dstIP = header.Dst

		if log.IsLevelEnabled(logger.TraceLevel) {
			log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
				header.Src, header.Dst, xip.Protocol(waterutil.IPv4Protocol(data)),
				header.Len, header.TotalLen, header.ID, header.Flags)
		}
	} else if waterutil.IsIPv6(data) {
		header, err := ipv6.ParseHeader(data)
		if err != nil {
			return err
		}

		dstIP = header.Dst

		if log.IsLevelEnabled(logger.TraceLevel) {
			log.Tracef("%s >> %s %s %d %d",
				header.Src, header.Dst,
				xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
				header.PayloadLen, header.TrafficClass)
		}
	} else {
		// Not an IP packet — cannot route.
		return fmt.Errorf("unknown packet, discarded(%d)", len(data))
	}

	rid := routerID.String()

	// ---- Route lookup ----
	route := h.getRoute(ctx, rid, dstIP.String())
	if route == nil || route.Gateway == "" {
		// No route to host, discard.
		return fmt.Errorf("no route to host %s", dstIP)
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Tracef("route for %s: %s -> %s", dstIP, route.Dst, route.Gateway)
	}

	// ---- Try local connector ----
	// If there's a connector for this gateway, the destination host is
	// behind a client connected to this node — write directly.
	if c := h.pool.Get(routerID, route.Gateway); c != nil {
		if w := c.Writer(); w != nil {
			if _, werr := w.Write(data); werr != nil {
				log.Error(werr)
			}
		}
		return nil
	}

	// ---- Fallback: forward to another node via entrypoint ----
	// The destination host is not behind any client of this node. Look
	// up a peer node that handles this gateway and forward via UDP.
	raddr := h.getAddrforRoute(ctx, rid, route.Gateway)
	if raddr == nil {
		return nil
	}

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.TunnelFeature{
				ID: routerID,
			},
			&relay.AddrFeature{
				AType: relay.AddrDomain,
				Host:  route.Gateway,
			},
		},
	}

	buf := bytes.Buffer{}
	req.WriteTo(&buf)
	buf.Write(data)

	if _, werr := h.epConn.WriteTo(buf.Bytes(), raddr); werr != nil {
		log.Error(werr)
	}

	return nil
}

// getRoute resolves a route for the given destination IP.
//
// # Lookup order
//
//  1. Route cache (if enabled) — fast path for recently seen destinations.
//  2. Registry lookup by router ID — looks up the router registered
//     under the given ID string.
//  3. Fallback router (metadata.router) — used when no specific router
//     is registered for the ID.
//
// When route caching is enabled, successful lookups are cached with
// the configured expiration time.
func (h *routerHandler) getRoute(ctx context.Context, rid string, dst string) *router.Route {
	if h.md.routerCacheEnabled {
		if item := h.routeCache.Get(dst); item != nil && !item.Expired() {
			v, _ := item.Value().(*router.Route)
			return v
		}
	}

	var route *router.Route
	if r := registry.RouterRegistry().Get(rid); r != nil {
		route = r.GetRoute(ctx, dst, router.IDOption(rid))
	}
	if route == nil && h.md.router != nil {
		route = h.md.router.GetRoute(ctx, dst, router.IDOption(rid))
	}

	if h.md.routerCacheEnabled {
		h.routeCache.Set(dst, cache.NewItem(route, h.md.routerCacheExpiration))
	}
	return route
}

// getAddrforRoute resolves the UDP address of a peer node that handles
// the given gateway, using service discovery.
//
// # Lookup order
//
//  1. SD cache — fast path for recently resolved addresses.
//  2. Service discovery — queries the SD backend for services matching
//     "gateway@routerID". Skips entries belonging to the current node
//     (we don't forward to ourselves).
//  3. DNS resolution — resolves the service address to a UDP address.
//
// Returns nil if SD is not configured or no peer is found.
func (h *routerHandler) getAddrforRoute(ctx context.Context, routerID, gateway string) net.Addr {
	if h.md.sd == nil {
		return nil
	}
	clientID := fmt.Sprintf("%s@%s", gateway, routerID)

	if item := h.sdCache.Get(clientID); item != nil && !item.Expired() {
		addr, _ := item.Value().(net.Addr)
		return addr
	}

	ss, _ := h.md.sd.Get(ctx, clientID)

	service := &sd.Service{}
	for _, s := range ss {
		if s.Node != h.id {
			service = s
			break
		}
	}
	// ResolveUDPAddr may fail if service.Address is empty (e.g., all
	// services were on the local node). In that case raddr is nil,
	// causing the caller to silently drop the packet.
	raddr, _ := net.ResolveUDPAddr("udp", service.Address)
	h.sdCache.Set(clientID, cache.NewItem(raddr, h.md.sdCacheExpiration))

	return raddr
}
