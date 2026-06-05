package udp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
)

// ListenConfig configures a UDP-to-TCP-stream listener.
type ListenConfig struct {
	Addr           net.Addr
	Backlog        int
	ReadQueueSize  int
	ReadBufferSize int
	TTL            time.Duration
	Keepalive      bool
	Stateless      bool
	Logger         logger.Logger
}
type listener struct {
	conn     net.PacketConn
	cqueue   chan net.Conn
	connPool *connPool
	closed   chan struct{}
	errChan  chan error
	config   *ListenConfig
}

// NewListener creates a net.Listener from a net.PacketConn by demultiplexing
// UDP datagrams into per-client net.Conn streams. Idle connections are cleaned
// up according to cfg.TTL.
//
// When cfg.Stateless is true, the listener operates in raw datagram mode:
// no connPool, no listenLoop goroutine, no per-client session tracking.
// Each Accept call blocks on a ReadFrom and returns a lightweight
// datagramConn wrapping a single packet.
func NewListener(conn net.PacketConn, cfg *ListenConfig) net.Listener {
	if cfg == nil {
		cfg = &ListenConfig{}
	}

	ln := &listener{
		conn:    conn,
		closed:  make(chan struct{}),
		errChan: make(chan error, 1),
		config:  cfg,
	}

	if cfg.Stateless {
		return ln
	}

	ln.cqueue = make(chan net.Conn, cfg.Backlog)
	ln.connPool = newConnPool(cfg.TTL).WithLogger(cfg.Logger)
	go ln.listenLoop()

	return ln
}

func (ln *listener) Accept() (conn net.Conn, err error) {
	if ln.config.Stateless {
		return ln.acceptStateless()
	}

	select {
	case conn = <-ln.cqueue:
		return
	case <-ln.closed:
		return nil, net.ErrClosed
	case err = <-ln.errChan:
		if err == nil {
			err = net.ErrClosed
		}
		return
	}
}

func (ln *listener) acceptStateless() (net.Conn, error) {
	b := bufpool.Get(ln.config.ReadBufferSize)

	n, raddr, err := ln.conn.ReadFrom(b)
	if err != nil {
		bufpool.Put(b)
		// Surface the error so the service loop can decide whether to
		// continue accepting.
		select {
		case <-ln.closed:
			return nil, net.ErrClosed
		default:
		}
		return nil, err
	}

	return &datagramConn{
		pc:         ln.conn,
		data:       b[:n],
		localAddr:  ln.Addr(),
		remoteAddr: raddr,
	}, nil
}

func (ln *listener) listenLoop() {
	for {
		select {
		case <-ln.closed:
			return
		default:
		}

		b := bufpool.Get(ln.config.ReadBufferSize)

		n, raddr, err := ln.conn.ReadFrom(b)
		if err != nil {
			ln.errChan <- err
			close(ln.errChan)
			return
		}

		c := ln.getConn(raddr)
		if c == nil {
			bufpool.Put(b)
			continue
		}

		if err := c.WriteQueue(b[:n]); err != nil {
			ln.config.Logger.Warn("data discarded: ", err)
		}
	}
}

func (ln *listener) Addr() net.Addr {
	if ln.config.Addr != nil {
		return ln.config.Addr
	}
	return ln.conn.LocalAddr()
}

func (ln *listener) Close() error {
	select {
	case <-ln.closed:
	default:
		close(ln.closed)
		ln.conn.Close()
		ln.connPool.Close()
	}

	return nil
}

func (ln *listener) getConn(raddr net.Addr) *conn {
	c, ok := ln.connPool.Get(raddr.String())
	if ok && !c.isClosed() {
		return c
	}

	c = newConn(ln.conn, ln.Addr(), raddr, ln.config.ReadQueueSize, ln.config.Keepalive)
	select {
	case ln.cqueue <- c:
		ln.connPool.Set(raddr.String(), c)
		return c
	default:
		c.Close()
		ln.config.Logger.Warnf("connection queue is full, client %s discarded", raddr)
		return nil
	}
}

// conn is a server side connection for UDP client peer, it implements net.Conn and net.PacketConn.
type conn struct {
	net.PacketConn
	localAddr  net.Addr
	remoteAddr net.Addr
	rc         chan []byte // data receive queue
	idle       int32       // indicate the connection is idle
	closed     chan struct{}
	closeMutex sync.Mutex
	keepalive  bool
}

func newConn(c net.PacketConn, laddr, remoteAddr net.Addr, queueSize int, keepalive bool) *conn {
	return &conn{
		PacketConn: c,
		localAddr:  laddr,
		remoteAddr: remoteAddr,
		rc:         make(chan []byte, queueSize),
		closed:     make(chan struct{}),
		keepalive:  keepalive,
	}
}

func (c *conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case bb := <-c.rc:
		n = copy(b, bb)
		c.SetIdle(false)
		bufpool.Put(bb)

	case <-c.closed:
		err = net.ErrClosed
		return
	}

	addr = c.remoteAddr

	return
}

func (c *conn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *conn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if !c.keepalive {
		defer c.Close()
	}
	c.SetIdle(false)

	return c.PacketConn.WriteTo(b, addr)
}

func (c *conn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.remoteAddr)
}

func (c *conn) Close() error {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()

	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *conn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) IsIdle() bool {
	return atomic.LoadInt32(&c.idle) > 0
}

func (c *conn) SetIdle(idle bool) {
	v := int32(0)
	if idle {
		v = 1
	}
	atomic.StoreInt32(&c.idle, v)
}

func (c *conn) WriteQueue(b []byte) error {
	select {
	case c.rc <- b:
		c.SetIdle(false)
		return nil

	case <-c.closed:
		return net.ErrClosed

	default:
		return errors.New("recv queue is full")
	}
}

// datagramConn is a lightweight net.Conn that wraps a single UDP datagram.
// It is used in stateless mode where each Accept returns a new datagramConn
// for a single packet — no channels, no mutexes, no pool tracking.
type datagramConn struct {
	pc         net.PacketConn
	data       []byte
	offset     int
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *datagramConn) Read(b []byte) (n int, err error) {
	if c.data == nil || c.offset >= len(c.data) {
		return 0, net.ErrClosed
	}
	n = copy(b, c.data[c.offset:])
	c.offset += n
	return
}

func (c *datagramConn) Write(b []byte) (n int, err error) {
	return c.pc.WriteTo(b, c.remoteAddr)
}

// ReadFrom implements net.PacketConn. It reads the buffered datagram and
// returns the sender's address.
func (c *datagramConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(b)
	addr = c.remoteAddr
	return
}

// WriteTo implements net.PacketConn. It sends b to addr via the underlying
// PacketConn, ignoring the stored remoteAddr.
func (c *datagramConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, addr)
}

func (c *datagramConn) Close() error {
	bufpool.Put(c.data)
	c.data = nil
	return nil
}

func (c *datagramConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *datagramConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *datagramConn) SetDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *datagramConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *datagramConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}
