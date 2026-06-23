package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/relay"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	serial "github.com/go-gost/x/internal/util/serial"
	"github.com/go-gost/x/internal/util/sniffing"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleConnect processes a relay CmdConnect request.
//
// This is the core function of the relay handler: the client connects to a
// target address through the relay.
//
// Data flow:
//
//	handleConnect()
//	├─ 1. Clean address (unix/serial special handling)
//	├─ 2. Wrap traffic limiter + stats
//	├─ 3. Check target address is non-empty
//	├─ 4. Bypass check
//	├─ 5. Set consistent-hashing source (e.g. "host")
//	├─ 6. Dial by network type:
//	│   ├─ "unix"   → net.Dialer.DialContext("unix")
//	│   ├─ "serial" → serial.OpenPort()
//	│   └─ other    → h.options.Router.Dial()  ← chain routing
//	├─ 7. Send response header (noDelay controls timing)
//	│   ├─ noDelay=true  → write relay.Response immediately
//	│   └─ noDelay=false → buffer in wbuf, merged with first data packet
//	├─ 8. Wrap connection by network type:
//	│   ├─ UDP → udpConn (2-byte length prefix)
//	│   └─ TCP → tcpConn (passthrough)
//	├─ 9. Optional protocol sniffing:
//	│   ├─ HTTP → sniffer.HandleHTTP()
//	│   ├─ TLS  → sniffer.HandleTLS()
//	│   └─ other → continue to step 10
//	└─ 10. xnet.Pipe() bidir copy (client ↔ target)
//
// Key design decisions:
//   - noDelay: low-latency mode sends each write as an independent relay frame.
//     Without it, the relay response header is merged with the first data packet.
//   - Sniffing reads the first few bytes after connection to detect the protocol.
//     HTTP/TLS traffic can be MITM-decrypted or recorded.
//   - Route info (node chain) is recorded via ictx.ContextWithBuffer into ro.Route.
func (h *relayHandler) handleConnect(ctx context.Context, conn net.Conn, network, address string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	if network == "unix" || network == "serial" {
		if host, _, _ := net.SplitHostPort(address); host != "" {
			address = host
		}
	}

	log = log.WithFields(map[string]any{
		"dst":  address,
		"cmd":  "connect",
		"host": address,
	})

	log.Debugf("%s >> %s/%s", conn.RemoteAddr(), address, network)

	// --- Traffic limiter + stats wrapper ---
	// clientID is used as the key for traffic limiting and stats collection.
	{
		clientID := xctx.ClientIDFromContext(ctx)
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			conn,
			string(clientID),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.ServiceOption(h.options.Service),
			limiter.NetworkOption(network),
			limiter.AddrOption(address),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if address == "" {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		err = errors.New("target not specified")
		log.Error(err)
		return
	}

	// Bypass check — if the target is in the bypass list, return Forbidden
	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, network, address, bypass.WithService(h.options.Service)) {
		log.Debug("bypass: ", address)
		resp.Status = relay.StatusForbidden
		resp.WriteTo(conn)
		return xbypass.ErrBypass
	}

	// Consistent hashing — used for sticky sessions across upstream nodes
	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: address})
	}

	// --- Dial to target ---
	var cc net.Conn
	switch network {
	case "unix":
		cc, err = (&net.Dialer{}).DialContext(ctx, "unix", address)
	case "serial":
		var port io.ReadWriteCloser
		port, err = serial.OpenPort(serial.ParseConfigFromAddr(address))
		if err == nil {
			cc = &serialConn{
				ReadWriteCloser: port,
				port:            address,
			}
		}
	default:
		var buf bytes.Buffer
		cc, err = h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, address)
		ro.Route = buf.String()
	}
	if err != nil {
		resp.Status = relay.StatusNetworkUnreachable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	// --- Send relay response header ---
	if h.md.noDelay {
		if _, err := resp.WriteTo(conn); err != nil {
			log.Error(err)
			return err
		}
	}

	// --- Wrap connection by network type ---
	// UDP connections use a 2-byte length prefix for datagram framing.
	// TCP connections pass data through directly.
	switch network {
	case "udp", "udp4", "udp6":
		rc := &udpConn{
			Conn: conn,
		}
		if !h.md.noDelay {
			// Buffer the response header, merged with the first data packet.
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
		}
		conn = rc
	default:
		if !h.md.noDelay {
			rc := &tcpConn{
				Conn: conn,
			}
			// Buffer the response header, merged with the first data packet.
			if _, err := resp.WriteTo(&rc.wbuf); err != nil {
				return err
			}
			conn = rc
		}
	}

	// --- Optional protocol sniffing ---
	// After connection establishment, sniff the first bytes of client traffic
	// to detect HTTP or TLS. When detected, MITM decryption can be applied.
	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return cc, nil
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return cc, nil
		}
		sniffer := &sniffing.Sniffer{
			Websocket:           h.md.sniffingWebsocket,
			WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
			Recorder:            h.recorder.Recorder,
			RecorderOptions:     h.recorder.Options,
			Certificate:         h.md.certificate,
			PrivateKey:          h.md.privateKey,
			NegotiatedProtocol:  h.md.alpn,
			CertPool:            h.certPool,
			MitmBypass:          h.md.mitmBypass,
			ReadTimeout:         h.md.readTimeout,
		}

		conn = xnet.NewReadWriteConn(br, conn, conn)
		switch proto {
		case sniffing.ProtoHTTP:
			return sniffer.HandleHTTP(ctx, "tcp", conn,
				sniffing.WithService(h.options.Service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithBypass(h.options.Bypass),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		case sniffing.ProtoTLS:
			return sniffer.HandleTLS(ctx, "tcp", conn,
				sniffing.WithService(h.options.Service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithBypass(h.options.Bypass),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		}
	}

	// --- Bidirectional data copy ---
	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), address)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), address)

	return nil
}

// serialConn wraps a serial port connection as net.Conn.
// Serial ports have no network addresses, so LocalAddr/RemoteAddr return
// custom serialAddr values. Deadline methods are no-ops since serial
// ports do not support deadlines.
type serialConn struct {
	io.ReadWriteCloser
	port string
}

func (c *serialConn) LocalAddr() net.Addr {
	return &serialAddr{
		port: "@",
	}
}

func (c *serialConn) RemoteAddr() net.Addr {
	return &serialAddr{
		port: c.port,
	}
}

func (c *serialConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *serialConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *serialConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// serialAddr is the address type for a serial port connection.
type serialAddr struct {
	port string
}

func (a *serialAddr) Network() string {
	return "serial"
}

func (a *serialAddr) String() string {
	return a.port
}
