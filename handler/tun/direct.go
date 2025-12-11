package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	directUDPTimeout   = 30 * time.Second
	directBufferSize   = 4096
	defaultOutQueueLen = 1 << 10
)

type directForwarder struct {
	mu      sync.Mutex
	started bool
	in      chan []byte
	cancel  context.CancelFunc
}

func newDirectForwarder() *directForwarder {
	return &directForwarder{in: make(chan []byte, 256)}
}

func (d *directForwarder) start(ctx context.Context, tun net.Conn, mtu int, log logger.Logger, opts *handler.Options, tunMu *sync.Mutex) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return nil
	}

	rw := &packetRW{in: d.in, tun: tun, tunMu: tunMu}
	ep := newDirectEndpoint(rw, mtu, log)
	th := newDirectTransport(opts, log)

	sctx, cancel := context.WithCancel(ctx)
	stackInst, err := core.CreateStack(&core.Config{
		LinkEndpoint:     ep,
		TransportHandler: th,
	})
	if err != nil {
		cancel()
		return err
	}

	d.cancel = cancel
	d.started = true

	go func() {
		<-sctx.Done()
		stackInst.Close()
	}()
	go ep.Wait()
	go stackInst.Wait()

	return nil
}

func (d *directForwarder) inject(pkt []byte) bool {
	select {
	case d.in <- pkt:
		return true
	default:
		return false
	}
}

type packetRW struct {
	in    <-chan []byte
	tun   io.Writer
	tunMu *sync.Mutex
}

func (p *packetRW) Read(b []byte) (int, error) {
	pkt, ok := <-p.in
	if !ok {
		return 0, io.EOF
	}
	n := len(pkt)
	if n > len(b) {
		copy(b, pkt[:len(b)])
		return len(b), nil
	}
	copy(b, pkt)
	return n, nil
}

func (p *packetRW) Write(b []byte) (int, error) {
	p.tunMu.Lock()
	defer p.tunMu.Unlock()
	return p.tun.Write(b)
}

type directEndpoint struct {
	*channel.Endpoint

	rw     io.ReadWriter
	mtu    uint32
	offset int
	once   sync.Once
	wg     sync.WaitGroup
	log    logger.Logger
}

func newDirectEndpoint(rw io.ReadWriter, mtu int, log logger.Logger) *directEndpoint {
	return &directEndpoint{
		Endpoint: channel.New(defaultOutQueueLen, uint32(mtu), ""),
		rw:       rw,
		mtu:      uint32(mtu),
		log:      log,
	}
}

func (e *directEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		e.wg.Add(2)
		go func() {
			e.outboundLoop(ctx)
			e.wg.Done()
		}()
		go func() {
			e.dispatchLoop(cancel)
			e.wg.Done()
		}()
	})
}

func (e *directEndpoint) Wait() {
	e.wg.Wait()
}

func (e *directEndpoint) dispatchLoop(cancel context.CancelFunc) {
	defer cancel()

	offset, mtu := e.offset, int(e.mtu)

	for {
		data := make([]byte, offset+mtu)

		n, err := e.rw.Read(data)
		if err != nil {
			e.log.Error(err)
			break
		}

		if e.log.IsLevelEnabled(logger.TraceLevel) {
			e.log.Tracef("read: (%d) % x", n, data[:n])
		}

		if n == 0 || n > mtu {
			continue
		}

		if !e.IsAttached() {
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data[offset : offset+n]),
		})

		switch header.IPVersion(data[offset:]) {
		case header.IPv4Version:
			e.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case header.IPv6Version:
			e.InjectInbound(header.IPv6ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
}

func (e *directEndpoint) outboundLoop(ctx context.Context) {
	for {
		pkt := e.ReadContext(ctx)
		if pkt == nil {
			break
		}
		e.writePacket(pkt)
	}
}

func (e *directEndpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	defer buf.Release()
	if e.offset != 0 {
		v := buffer.NewViewWithData(make([]byte, e.offset))
		_ = buf.Prepend(v)
	}

	if _, err := e.rw.Write(buf.Flatten()); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}

	return nil
}

type directTransport struct {
	opts       *handler.Options
	udpTimeout time.Duration
	log        logger.Logger
}

func newDirectTransport(opts *handler.Options, log logger.Logger) *directTransport {
	return &directTransport{
		opts:       opts,
		udpTimeout: directUDPTimeout,
		log:        log,
	}
}

func (h *directTransport) HandleTCP(conn adapter.TCPConn) {
	go h.handleTCPConn(conn)
}

func (h *directTransport) HandleUDP(conn adapter.UDPConn) {
	go h.handleUDPConn(conn)
}

func (h *directTransport) handleTCPConn(originConn adapter.TCPConn) {
	defer originConn.Close()

	id := originConn.ID()

	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	remoteAddr := netip.AddrPortFrom(remoteIP, id.RemotePort)
	dstAddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	ctx := context.Background()

	network := "tcp"
	if dstIP.Unmap().Is6() {
		network = "tcp6"
	}

	log := h.log.WithFields(map[string]any{
		"network": network,
		"remote":  remoteAddr.String(),
		"dst":     dstAddr.String(),
	})

	d := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0x100)
				if err != nil {
					h.log.Errorf("TCP: Failed to set SO_MARK: %v", err)
				} else {
					h.log.Debugf("TCP: Set SO_MARK 0x100 for %s -> %s", network, address)
				}
			})
		},
	}
	cc, err := d.DialContext(ctx, network, dstAddr.String())
	if err != nil {
		log.Errorf("dial %s: %v", dstAddr.String(), err)
		return
	}
	defer cc.Close()

	log.Infof("%s <-> %s", remoteAddr, dstAddr)
	xnet.Pipe(ctx, originConn, cc)
	log.Infof("%s >-< %s", remoteAddr, dstAddr)
}

func (h *directTransport) handleUDPConn(uc adapter.UDPConn) {
	defer uc.Close()

	id := uc.ID()

	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	remoteAddr := netip.AddrPortFrom(remoteIP, id.RemotePort)
	dstAddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	ctx := context.Background()

	log := h.log.WithFields(map[string]any{
		"network": "udp",
		"remote":  remoteAddr.String(),
		"dst":     dstAddr.String(),
	})

	d := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0x100)
				if err != nil {
					h.log.Errorf("UDP: Failed to set SO_MARK: %v", err)
				} else {
					h.log.Debugf("UDP: Set SO_MARK 0x100 for %s -> %s", network, address)
				}
			})
		},
	}
	cc, err := d.DialContext(ctx, "udp", dstAddr.String())
	if err != nil {
		log.Errorf("dial %s: %v", dstAddr.String(), err)
		return
	}
	defer cc.Close()

	log.Infof("%s <-> %s", remoteAddr, dstAddr)
	h.pipePacketData(uc, cc, ctx)
	log.Infof("%s >-< %s", remoteAddr, dstAddr)
}

func (h *directTransport) pipePacketData(conn1, conn2 net.Conn, ctx context.Context) {
	timeout := h.udpTimeout
	if timeout <= 0 {
		timeout = directUDPTimeout
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := bufpool.Get(directBufferSize)
		defer bufpool.Put(buf)
		copyPacketData(conn1, conn2, buf, timeout)
	}()

	go func() {
		defer wg.Done()
		buf := bufpool.Get(directBufferSize)
		defer bufpool.Put(buf)
		copyPacketData(conn2, conn1, buf, timeout)
	}()

	wg.Wait()
}

func copyPacketData(dst, src net.Conn, buf []byte, timeout time.Duration) error {
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		} else if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if n == 0 {
			return nil
		}

		if _, err = dst.Write(buf[:n]); err != nil {
			return err
		}
		_ = dst.SetReadDeadline(time.Now().Add(timeout))
	}
}
