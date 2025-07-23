package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
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

	log logger.Logger
}

func newTransportHandler(log logger.Logger) *transportHandler {
	return &transportHandler{
		tcpQueue:   make(chan adapter.TCPConn),
		udpQueue:   make(chan adapter.UDPConn),
		udpTimeout: atomic.NewDuration(udpSessionTimeout),
		procCancel: func() { /* nop */ },
		log:        log,
	}
}

func (t *transportHandler) HandleTCP(conn adapter.TCPConn) {
	t.tcpQueue <- conn
}

func (t *transportHandler) HandleUDP(conn adapter.UDPConn) {
	t.udpQueue <- conn
}

func (t *transportHandler) process(ctx context.Context) {
	for {
		select {
		case conn := <-t.tcpQueue:
			go t.handleTCPConn(conn)
		case conn := <-t.udpQueue:
			go t.handleUDPConn(conn)
		case <-ctx.Done():
			return
		}
	}
}

// ProcessAsync can be safely called multiple times, but will only be effective once.
func (t *transportHandler) ProcessAsync() {
	t.procOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		t.procCancel = cancel
		go t.process(ctx)
	})
}

// Close closes the Tunnel and releases its resources.
func (t *transportHandler) Close() {
	t.procCancel()
}

func (t *transportHandler) SetUDPTimeout(timeout time.Duration) {
	t.udpTimeout.Store(timeout)
}

func (t *transportHandler) handleTCPConn(originConn adapter.TCPConn) {
	defer originConn.Close()

	id := originConn.ID()

	srcIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	raddr := netip.AddrPortFrom(srcIP, id.RemotePort)
	laddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	t.log.Debugf("[TCP] %s <-> %s", raddr.String(), laddr.String())
}

// TODO: Port Restricted NAT support.
func (t *transportHandler) handleUDPConn(uc adapter.UDPConn) {
	defer uc.Close()
}
