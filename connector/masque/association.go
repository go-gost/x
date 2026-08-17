package masque

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
)

const udpAssociationBufferSize = 64 * 1024

var errMissingDestination = errors.New("masque: destination address required")

type udpAssociationDialFunc func(ctx context.Context, addr net.Addr) (net.PacketConn, error)

type udpAssociationResult struct {
	data []byte
	addr net.Addr
}

type udpAssociationTunnel struct {
	conn net.PacketConn
}

type udpAssociationConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	localAddr net.Addr
	dial      udpAssociationDialFunc
	closeIdle func() error
	log       logger.Logger
	timeout   time.Duration

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
	results   chan udpAssociationResult

	mu                  sync.Mutex
	tunnels             map[string]*udpAssociationTunnel
	readDeadline        time.Time
	readDeadlineChanged chan struct{}
}

func newUDPAssociationConn(
	ctx context.Context,
	localAddr net.Addr,
	timeout time.Duration,
	dial udpAssociationDialFunc,
	closeIdle func() error,
	log logger.Logger,
) *udpAssociationConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &udpAssociationConn{
		ctx:                 ctx,
		cancel:              cancel,
		localAddr:           localAddr,
		dial:                dial,
		closeIdle:           closeIdle,
		log:                 log,
		timeout:             timeout,
		closed:              make(chan struct{}),
		results:             make(chan udpAssociationResult, 32),
		tunnels:             make(map[string]*udpAssociationTunnel),
		readDeadlineChanged: make(chan struct{}),
	}
	return c
}

func (c *udpAssociationConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case <-c.closed:
			return 0, nil, net.ErrClosed
		default:
		}

		c.mu.Lock()
		deadline := c.readDeadline
		deadlineChanged := c.readDeadlineChanged
		c.mu.Unlock()

		var (
			timer   *time.Timer
			timeout <-chan time.Time
		)
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}

		select {
		case result := <-c.results:
			if timer != nil {
				timer.Stop()
			}
			return copy(b, result.data), result.addr, nil
		case <-deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *udpAssociationConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errMissingDestination
	}

	tunnel, err := c.tunnel(addr)
	if err != nil {
		if c.isClosed() {
			return 0, net.ErrClosed
		}
		c.logError(addr, err)
		return len(b), nil
	}
	n, err := tunnel.conn.WriteTo(b, addr)
	if err == nil {
		return n, nil
	}
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if c.removeTunnel(addr.String(), tunnel) {
		c.logError(addr, err)
	}
	return len(b), nil
}

func (c *udpAssociationConn) tunnel(addr net.Addr) (*udpAssociationTunnel, error) {
	key := addr.String()

	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}

	if tunnel := c.tunnels[key]; tunnel != nil {
		c.mu.Unlock()
		return tunnel, nil
	}
	c.mu.Unlock()

	ctx := c.ctx
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	conn, err := c.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("masque: nil UDP tunnel")
	}

	tunnel := &udpAssociationTunnel{conn: conn}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	default:
	}
	if current := c.tunnels[key]; current != nil {
		c.mu.Unlock()
		conn.Close()
		return current, nil
	}
	c.tunnels[key] = tunnel
	c.mu.Unlock()
	go c.readTunnel(key, tunnel)
	return tunnel, nil
}

func (c *udpAssociationConn) readTunnel(key string, tunnel *udpAssociationTunnel) {
	buf := make([]byte, udpAssociationBufferSize)
	for {
		n, addr, err := tunnel.conn.ReadFrom(buf)
		if err != nil {
			if c.isClosed() {
				return
			}
			if c.removeTunnel(key, tunnel) {
				c.logError(key, err)
			}
			return
		}

		data := append([]byte(nil), buf[:n]...)
		select {
		case c.results <- udpAssociationResult{data: data, addr: addr}:
		case <-c.closed:
			return
		}
	}
}

func (c *udpAssociationConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *udpAssociationConn) logError(addr any, err error) {
	if c.log != nil {
		c.log.Warnf("masque: UDP tunnel %v: %v", addr, err)
	}
}

func (c *udpAssociationConn) removeTunnel(key string, tunnel *udpAssociationTunnel) bool {
	c.mu.Lock()
	removed := c.tunnels[key] == tunnel
	if c.tunnels[key] == tunnel {
		delete(c.tunnels, key)
	}
	c.mu.Unlock()
	tunnel.conn.Close()
	return removed
}

func (c *udpAssociationConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpAssociationConn) Write(b []byte) (int, error) {
	return 0, errMissingDestination
}

func (c *udpAssociationConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.cancel()

		c.mu.Lock()
		close(c.readDeadlineChanged)
		tunnels := make([]*udpAssociationTunnel, 0, len(c.tunnels))
		for _, tunnel := range c.tunnels {
			tunnels = append(tunnels, tunnel)
		}
		clear(c.tunnels)
		c.mu.Unlock()

		var errs []error
		for _, tunnel := range tunnels {
			if err := tunnel.conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.closeIdle != nil {
			if err := c.closeIdle(); err != nil {
				errs = append(errs, err)
			}
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func (c *udpAssociationConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpAssociationConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *udpAssociationConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *udpAssociationConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	c.readDeadline = t
	close(c.readDeadlineChanged)
	c.readDeadlineChanged = make(chan struct{})
	return nil
}

func (c *udpAssociationConn) SetWriteDeadline(t time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	return nil
}

var (
	_ net.Conn       = (*udpAssociationConn)(nil)
	_ net.PacketConn = (*udpAssociationConn)(nil)
)
