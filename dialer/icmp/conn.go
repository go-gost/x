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

func (session *quicSession) GetConn() (*quicConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
