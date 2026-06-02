// Package entrypoint implements a public tunnel entry point that accepts external
// connections and routes them through the tunnel network to internal services
// behind NAT/firewall.
//
// Protocol dispatch is done by peeking at the first byte of the connection:
//
//	relay.Version1 (0x52 'R') → relay protocol  (handleConnect)
//	dissector.Handshake (0x16) → TLS passthrough (handleTLS)
//	otherwise                  → HTTP proxy      (handleHTTP)
//
// The entrypoint is constructed by the parent tunnel package via Config and a
// DialFunc. It operates as a standalone service with its own TCP listener,
// decoder wrapper, and protocol-specific handling — independent of the parent's
// relay-handshake path.
package entrypoint

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	dissector "github.com/go-gost/tls-dissector"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// entrypoint errors — mirror of tunnel.ErrTunnelRoute and tunnel.ErrPrivateTunnel
// to avoid import cycles. The parent package's dial function returns these.
var (
	errNoRoute       = fmt.Errorf("no route to host")
	errPrivateTunnel = fmt.Errorf("private tunnel")
)

// Entrypoint is a public tunnel entry point that accepts external connections
// and routes them through the tunnel network.
//
// Protocol dispatch is done by peeking at the first byte of the connection:
//   - relay.Version1 (0x52 'R') → relay protocol  (handleConnect)
//   - dissector.Handshake (0x16) → TLS passthrough (handleTLS)
//   - otherwise                  → HTTP proxy      (handleHTTP)
//
// For HTTP/TLS paths, the dial flow is:
//
//	ep.Dial() → ingress lookup (host → tunnelID) → dialFn()
//	  → tunnel connection
//
// The relay protocol path handles its own tunnel ID extraction from the
// relay request frame.
type Entrypoint struct {
	// node is the local tunnel node ID (from tunnelHandler.id).
	node string
	// service is the parent handler's service name, used for ingress lookups.
	service   string
	ingress   ingress.Ingress
	sd        sd.SD
	log       logger.Logger
	recorder  recorder.RecorderObject
	transport http.RoundTripper

	// sniffingWebsocket enables WebSocket frame-level recording.
	sniffingWebsocket   bool
	// websocketSampleRate controls the rate-limiter for WebSocket frame
	// recording samples. 0 defaults to sniffing.DefaultSampleRate.
	websocketSampleRate float64

	// readTimeout is applied as SetReadDeadline on the upstream connection
	// before sniffing HTTP/TLS reads. It mirrors entryPointReadTimeout
	// from the handler metadata.
	readTimeout time.Duration

	// dialFn is the function for establishing a tunnel connection,
	// provided by the parent package.
	dialFn DialFunc
}

// Handle processes an incoming connection on the entrypoint listener.
//
// The first byte is peeked to dispatch protocol handling:
//   - relay.Version1 (0x52 'R') → ep.handleConnect (relay protocol)
//   - dissector.Handshake (0x16) → ep.handleTLS (TLS passthrough)
//   - otherwise → ep.handleHTTP (HTTP forward proxy)
//
// Recording instrumentation (stats, HTTP/TLS metadata) wraps the connection
// and is finalized in the deferred recorder callback.
func (ep *Entrypoint) Handle(ctx context.Context, conn net.Conn) (err error) {
	defer conn.Close()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "tcp",
		Node:       ep.node,
		Service:    ep.service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		SID:        xctx.SidFromContext(ctx).String(),
		Time:       time.Now(),
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := ep.log.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})
	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	br := bufio.NewReader(conn)
	v, err := br.Peek(1)
	if err != nil {
		return err
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)
	if v[0] == relay.Version1 {
		return ep.handleConnect(ctx, conn, ro, log)
	}
	if v[0] == dissector.Handshake {
		return ep.handleTLS(ctx, conn, ro, log)
	}
	return ep.handleHTTP(ctx, conn, ro, log)
}

// dial resolves the host to a tunnel ID via ingress rules, then establishes
// a connection through the tunnel network using the provided dial function.
//
// Steps:
//  1. Look up addr in the ingress table to find the target tunnel ID.
//  2. If the tunnel ID is zero, return errNoRoute.
//  3. If the tunnel is private ($-prefixed), return errPrivateTunnel.
//  4. Call ep.dialFn(ctx, "tcp", tunnelID.String()) to open a tunnel stream.
//  5. If the connected node is the local node, write StatusOK + address
//     features (src, dst) to the stream — the internal client uses these
//     addresses to know where to connect.
//  6. If the connected node is remote, just set ro.Redirect — the remote
//     node handles relay framing on its own.
//
// Returns the tunnel stream as conn, or an error.
func (ep *Entrypoint) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var tunnelID relay.TunnelID
	if ep.ingress != nil {
		if rule := ep.ingress.GetRule(ctx, addr, ingress.WithService(ep.service)); rule != nil {
			tunnelID = parseTunnelID(rule.Endpoint)
		}
	}

	log := ictx.LoggerFromContext(ctx)
	if log == nil {
		log = ep.log
	}
	log.Debugf("dial: new connection to host %s", addr)

	if tunnelID.IsZero() {
		return nil, fmt.Errorf("%w %s", errNoRoute, addr)
	}

	if ro := ictx.RecorderObjectFromContext(ctx); ro != nil {
		ro.ClientID = tunnelID.String()
	}

	if tunnelID.IsPrivate() {
		return nil, fmt.Errorf("%w: tunnel %s is private for host %s", errPrivateTunnel, tunnelID, addr)
	}

	log = log.WithFields(map[string]any{
		"tunnel": tunnelID.String(),
	})

	if ep.dialFn == nil {
		return nil, fmt.Errorf("tunnel not available")
	}

	cc, node, cid, err := ep.dialFn(ctx, "tcp", tunnelID.String())
	if err != nil {
		return
	}
	log.Debugf("dial: connected to host %s, tunnel: %s, connector: %s", addr, tunnelID, cid)

	ro := ictx.RecorderObjectFromContext(ctx)
	if node == ep.node {
		if ro != nil {
			ro.Redirect = ""
		}

		var clientAddr string
		if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
			clientAddr = addr.String()
		}
		var features []relay.Feature
		af := &relay.AddrFeature{}
		af.ParseFrom(string(clientAddr))
		features = append(features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(addr)
		features = append(features, af) // dst address

		if _, err = (&relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: features,
		}).WriteTo(cc); err != nil {
			cc.Close()
			return nil, err
		}
	} else {
		if ro != nil {
			ro.Redirect = node
		}
	}

	conn = cc
	return conn, nil
}

// parseTunnelID parses a tunnel ID from a string.
// If s is empty or contains an invalid UUID, the returned tunnel ID is zero
// (callers must check IsZero). A leading '$' prefix marks the tunnel as private.
//
// This is a copy of tunnel.ParseTunnelID that avoids importing google/uuid.
// It uses a local parseUUID instead of uuid.Parse.
func parseTunnelID(s string) (tid relay.TunnelID) {
	if s == "" {
		return
	}
	private := false
	if s[0] == '$' {
		private = true
		s = s[1:]
	}
	u, err := parseUUID(s)
	if err != nil {
		return
	}
	var raw [16]byte
	copy(raw[:], u[:])

	if private {
		return relay.NewPrivateTunnelID(raw[:])
	}
	return relay.NewTunnelID(raw[:])
}

// parseUUID is a simplified UUID parser that avoids importing google/uuid.
// It parses the standard 8-4-4-4-12 hex format (36 characters) and returns
// the 16 raw bytes. An error is returned for invalid length, missing hyphens,
// or non-hex characters.
func parseUUID(s string) ([]byte, error) {
	if len(s) != 36 {
		return nil, fmt.Errorf("invalid UUID length")
	}
	b := make([]byte, 16)
	for i, j := 0, 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return nil, fmt.Errorf("invalid UUID format")
			}
			continue
		}
		var v byte
		switch {
		case s[i] >= '0' && s[i] <= '9':
			v = s[i] - '0'
		case s[i] >= 'a' && s[i] <= 'f':
			v = s[i] - 'a' + 10
		case s[i] >= 'A' && s[i] <= 'F':
			v = s[i] - 'A' + 10
		default:
			return nil, fmt.Errorf("invalid UUID character")
		}
		if j%2 == 0 {
			b[j/2] = v << 4
		} else {
			b[j/2] |= v
		}
		j++
	}
	return b, nil
}