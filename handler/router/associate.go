package router

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	xip "github.com/go-gost/x/internal/net/ip"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/google/uuid"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

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

	if ingress := h.md.ingress; ingress != nil && host != "" {
		var rid relay.TunnelID
		if rule := ingress.GetRule(ctx, host); rule != nil {
			rid = parseRouterID(rule.Endpoint)
		}

		if rid.IsZero() || !rid.Equal(routerID) {
			resp.Status = relay.StatusHostUnreachable
			resp.WriteTo(conn)
			err := fmt.Errorf("no route to host %s", host)
			log.Error(err)
			return err
		}
	}

	uuid, err := uuid.NewRandom()
	if err != nil {
		resp.Status = relay.StatusInternalServerError
		resp.WriteTo(conn)
		return
	}
	connectorID := relay.NewConnectorID(uuid[:])

	resp.Features = append(resp.Features,
		&relay.TunnelFeature{
			ID: connectorID,
		},
	)
	resp.WriteTo(conn)

	conn = &packetConn{conn}

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

	h.pool.Add(routerID, NewConnector(routerID, connectorID, host, LockWriter(conn), &ConnectorOptions{}))
	defer h.pool.Del(routerID, host, connectorID)

	if h.md.sd != nil {
		err := h.md.sd.Register(ctx, &sd.Service{
			ID:      connectorID.String(),
			Name:    clientID,
			Node:    h.id,
			Network: network,
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
	}

	log.Debugf("%s/%s: router=%s, connector=%s, weight=%d established", host, network, routerID, connectorID, connectorID.Weight())

	return h.routing(ctx, conn, routerID, log)
}

func (h *routerHandler) routing(ctx context.Context, conn net.Conn, routerID relay.TunnelID, log logger.Logger) error {
	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	rid := routerID.String()

	for {
		err := func() error {
			n, err := conn.Read(b)
			if err != nil {
				return err
			}

			var dstIP net.IP

			if waterutil.IsIPv4(b[:n]) {
				header, err := ipv4.ParseHeader(b[:n])
				if err != nil {
					log.Warn(err)
					return nil
				}

				dstIP = header.Dst

				if log.IsLevelEnabled(logger.TraceLevel) {
					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						header.Src, header.Dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				}
			} else if waterutil.IsIPv6(b[:n]) {
				header, err := ipv6.ParseHeader(b[:n])
				if err != nil {
					log.Warn(err)
					return nil
				}

				dstIP = header.Dst

				if log.IsLevelEnabled(logger.TraceLevel) {
					log.Tracef("%s >> %s %s %d %d",
						header.Src, header.Dst,
						xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				}
			} else {
				log.Warnf("unknown packet, discarded(%d)", n)
				return nil
			}

			var route *router.Route
			if r := registry.RouterRegistry().Get(rid); r != nil {
				route = r.GetRoute(ctx, dstIP, router.IDOption(rid))
			}
			if route == nil && h.md.router != nil {
				route = h.md.router.GetRoute(ctx, dstIP, router.IDOption(rid))
			}
			if route == nil || route.Gateway == "" {
				// no route to host, discard
				return nil
			}

			if log.IsLevelEnabled(logger.TraceLevel) {
				log.Tracef("route for %s: %s -> %s", dstIP, route.Dst, route.Gateway)
			}

			if c := h.pool.Get(routerID, route.Gateway); c != nil {
				if w := c.Writer(); w != nil {
					w.Write(b[:n])
				}
			}

			return nil
		}()
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
	}
}

type packetConn struct {
	net.Conn
}

func (c *packetConn) Read(b []byte) (n int, err error) {
	var bb [2]byte
	_, err = io.ReadFull(c.Conn, bb[:])
	if err != nil {
		return
	}

	dlen := int(binary.BigEndian.Uint16(bb[:]))
	if len(b) >= dlen {
		return io.ReadFull(c.Conn, b[:dlen])
	}

	buf := bufpool.Get(dlen)
	defer bufpool.Put(buf)

	n, err = io.ReadFull(c.Conn, buf)
	copy(b, buf[:n])

	return
}

func (c *packetConn) Write(b []byte) (n int, err error) {
	if len(b) > math.MaxUint16 {
		err = errors.New("write: data maximum exceeded")
		return
	}

	buf := bufpool.Get(len(b) + 2)
	defer bufpool.Put(buf)

	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	n = copy(buf[2:], b)

	return c.Conn.Write(buf)
}

type lockWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func LockWriter(w io.Writer) io.Writer {
	return &lockWriter{w: w}
}

func (w *lockWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.w.Write(p)
}

func (w *lockWriter) Close() error {
	if closer, ok := w.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
