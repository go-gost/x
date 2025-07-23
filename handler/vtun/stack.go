package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/observer/stats"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/rs/xid"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"go.uber.org/atomic"
)

const (
	// tcpConnectTimeout is the default timeout for TCP handshakes.
	tcpConnectTimeout = 5 * time.Second
	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 60 * time.Second
	// udpSessionTimeout is the default timeout for UDP sessions.
	udpSessionTimeout = 60 * time.Second
)

var _ adapter.TransportHandler = (*transportHandler)(nil)

type transportHandler struct {
	// Unbuffered TCP/UDP queues.
	tcpQueue chan adapter.TCPConn
	udpQueue chan adapter.UDPConn

	// UDP session timeout.
	udpTimeout *atomic.Duration

	procOnce   sync.Once
	procCancel context.CancelFunc

	opts *handler.Options
}

func newTransportHandler(opts *handler.Options) *transportHandler {
	return &transportHandler{
		tcpQueue:   make(chan adapter.TCPConn),
		udpQueue:   make(chan adapter.UDPConn),
		udpTimeout: atomic.NewDuration(udpSessionTimeout),
		procCancel: func() { /* nop */ },

		opts: opts,
	}
}

func (h *transportHandler) HandleTCP(conn adapter.TCPConn) {
	h.tcpQueue <- conn
}

func (h *transportHandler) HandleUDP(conn adapter.UDPConn) {
	h.udpQueue <- conn
}

func (h *transportHandler) process(ctx context.Context) {
	for {
		select {
		case conn := <-h.tcpQueue:
			go h.handleTCPConn(conn)
		case conn := <-h.udpQueue:
			go h.handleUDPConn(conn)
		case <-ctx.Done():
			return
		}
	}
}

// ProcessAsync can be safely called multiple times, but will only be effective once.
func (h *transportHandler) ProcessAsync() {
	h.procOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		h.procCancel = cancel
		go h.process(ctx)
	})
}

// Close closes the Tunnel and releases its resources.
func (h *transportHandler) Close() {
	h.procCancel()
}

func (h *transportHandler) SetUDPTimeout(timeout time.Duration) {
	h.udpTimeout.Store(timeout)
}

func (h *transportHandler) handleTCPConn(originConn adapter.TCPConn) {
	defer originConn.Close()

	id := originConn.ID()

	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	remoteAddr := netip.AddrPortFrom(remoteIP, id.RemotePort)
	dstAddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	start := time.Now()

	sid := xid.New().String()
	ctx := ctxvalue.ContextWithSid(context.Background(), ctxvalue.Sid(sid))

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.opts.Service,
		Network:    "tcp",
		RemoteAddr: remoteAddr.String(),
		Dst:        dstAddr.String(),
		Time:       start,
		SID:        sid,
	}
	log := h.opts.Logger.WithFields(map[string]any{"network": "tcp", "sid": ro.SID})

	log.Debugf("%s <> %s", remoteAddr.String(), dstAddr.String())

	var err error
	var conn net.Conn = originConn

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", remoteAddr.String(), dstAddr.String())
	}()

	cc, err := h.opts.Router.Dial(ctx, "tcp", dstAddr.String())
	if err != nil {
		log.Errorf("dial %s: %v", dstAddr.String(), err)
		return
	}
	defer cc.Close()

	ro.Src = cc.LocalAddr().String()

	t := time.Now()
	log.Infof("%s <-> %s", remoteAddr, dstAddr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", remoteAddr, dstAddr)
}

// TODO: Port Restricted NAT support.
func (t *transportHandler) handleUDPConn(uc adapter.UDPConn) {
	defer uc.Close()
}
