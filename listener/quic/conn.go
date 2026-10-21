package quic

import (
	"net"

	"github.com/quic-go/quic-go"
)

type quicConn struct {
	*quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.raddr
}

// Close closes both directions of the stream.
//
// quic.Stream.Close only closes the send direction. Without CancelRead, data
// the peer has already sent stays unread in the stream and keeps occupying the
// connection-level flow control window. When the local side abandons a
// transfer, this leaks window credit; once the window is exhausted the peer
// cannot send data on any stream and every connection over the session stalls,
// while the session itself stays alive.
func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

// CloseRead stops reading from the stream and returns buffered data to the
// flow control window.
func (c *quicConn) CloseRead() error {
	c.Stream.CancelRead(0)
	return nil
}

// CloseWrite closes the send direction of the stream, leaving the receive
// direction open. It is the QUIC equivalent of a TCP half-close: the peer
// sees the end of the request, and the response can still be read.
func (c *quicConn) CloseWrite() error {
	return c.Stream.Close()
}
