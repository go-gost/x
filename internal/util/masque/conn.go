package masque

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// DatagramStreamer is an interface for sending and receiving HTTP/3 datagrams.
// Both http3.Stream and http3.RequestStream implement this interface.
type DatagramStreamer interface {
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// DatagramConn wraps an HTTP/3 stream's datagram methods as net.PacketConn.
// This allows UDP packets to be tunneled over HTTP/3 datagrams per RFC 9297/9298.
type DatagramConn struct {
	stream     DatagramStreamer
	closer     io.Closer // Optional closer for the underlying stream
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     chan struct{}
	closeOnce  sync.Once

	mu           sync.RWMutex
	readDeadline time.Time
}

// NewDatagramConn creates a new DatagramConn wrapping an HTTP/3 stream.
func NewDatagramConn(stream *http3.Stream, laddr, raddr net.Addr) *DatagramConn {
	return &DatagramConn{
		stream:     stream,
		localAddr:  laddr,
		remoteAddr: raddr,
		closed:     make(chan struct{}),
	}
}

// NewDatagramConnFromRequestStream creates a new DatagramConn wrapping an HTTP/3 request stream.
// This is used by the client-side connector. The stream will be closed when Close() is called.
func NewDatagramConnFromRequestStream(stream *http3.RequestStream, laddr, raddr net.Addr) *DatagramConn {
	return &DatagramConn{
		stream:     stream,
		closer:     stream, // RequestStream implements io.Closer
		localAddr:  laddr,
		remoteAddr: raddr,
		closed:     make(chan struct{}),
	}
}

// ReadFrom reads a UDP datagram from the HTTP/3 stream.
// Per RFC 9297, HTTP datagrams have a context ID prefix.
// For CONNECT-UDP (RFC 9298), the context ID is 0.
func (c *DatagramConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}

	ctx := context.Background()
	c.mu.RLock()
	deadline := c.readDeadline
	c.mu.RUnlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	data, err := c.stream.ReceiveDatagram(ctx)
	if err != nil {
		return 0, nil, err
	}

	if len(data) == 0 {
		return 0, c.remoteAddr, nil
	}

	// Per RFC 9297: datagram format is context-id (varint) + payload
	// For CONNECT-UDP with context ID 0, the first byte is 0x00
	// We strip the context ID prefix
	if data[0] == 0x00 {
		data = data[1:]
	}

	n = copy(b, data)
	return n, c.remoteAddr, nil
}

// WriteTo sends a UDP datagram via the HTTP/3 stream.
// Per RFC 9297, we prepend the context ID (0x00 for CONNECT-UDP).
func (c *DatagramConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	// Prepend context ID (0x00 for context ID 0)
	datagram := make([]byte, 1+len(b))
	datagram[0] = 0x00 // Context ID = 0
	copy(datagram[1:], b)

	if err := c.stream.SendDatagram(datagram); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Read reads data from the connection (net.Conn interface).
func (c *DatagramConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

// Write writes data to the connection (net.Conn interface).
func (c *DatagramConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.remoteAddr)
}

// Close closes the datagram connection and the underlying stream.
func (c *DatagramConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.closer != nil {
			err = c.closer.Close()
		}
	})
	return err
}

// LocalAddr returns the local network address.
func (c *DatagramConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address.
func (c *DatagramConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *DatagramConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *DatagramConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline.
// Note: Write deadlines are not used for HTTP/3 datagrams as SendDatagram is non-blocking.
func (c *DatagramConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Ensure DatagramConn implements both net.Conn and net.PacketConn
var (
	_ net.Conn       = (*DatagramConn)(nil)
	_ net.PacketConn = (*DatagramConn)(nil)
)
