package quic

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type quicSession struct {
	session *quic.Conn
}

func (session *quicSession) GetConn(ctx context.Context) (*quicConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := session.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{
		Stream: stream,
		laddr:  session.session.LocalAddr(),
		raddr:  session.session.RemoteAddr(),
	}, nil
}

func (session *quicSession) IsClosed() bool {
	select {
	case <-session.session.Context().Done():
		return true
	default:
		return false
	}
}

func (session *quicSession) Close() error {
	return session.session.CloseWithError(quic.ApplicationErrorCode(0), "closed")
}

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
// connection-level flow control window. When a local app aborts a download,
// this leaks window credit; once the window is exhausted the peer cannot send
// data on any stream and every connection over the session stalls, while the
// session itself stays alive.
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
