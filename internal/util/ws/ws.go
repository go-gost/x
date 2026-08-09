package ws

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	ctx_pkg "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	"github.com/gorilla/websocket"
)

type WebsocketConn interface {
	net.Conn
	WriteMessage(int, []byte) error
	ReadMessage() (int, []byte, error)
	xio.CloseRead
	xio.CloseWrite
}

type websocketConn struct {
	*websocket.Conn
	r   io.Reader
	ctx context.Context
	mux sync.Mutex
}

func Conn(conn *websocket.Conn) WebsocketConn {
	ctx := context.Background()
	if cc, ok := conn.NetConn().(ctx_pkg.Context); ok {
		if cv := cc.Context(); cv != nil {
			ctx = cv
		}
	}
	return ContextConn(ctx, conn)
}

func ContextConn(ctx context.Context, conn *websocket.Conn) WebsocketConn {
	return &websocketConn{
		Conn: conn,
		ctx:  ctx,
	}
}

func (c *websocketConn) Read(b []byte) (n int, err error) {
	for {
		if c.r == nil {
			_, c.r, err = c.Conn.NextReader()
			if err != nil {
				return 0, err
			}
		}

		n, err = c.r.Read(b)
		if err == io.EOF {
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *websocketConn) Write(b []byte) (n int, err error) {
	err = c.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *websocketConn) WriteMessage(messageType int, data []byte) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	return c.Conn.WriteMessage(messageType, data)
}

func (c *websocketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *websocketConn) SetReadDeadline(t time.Time) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *websocketConn) CloseRead() error {
	if sc, ok := c.Conn.NetConn().(xio.CloseRead); ok {
		return sc.CloseRead()
	}
	return xio.ErrUnsupported
}

func (c *websocketConn) CloseWrite() error {
	if sc, ok := c.Conn.NetConn().(xio.CloseWrite); ok {
		return sc.CloseWrite()
	}
	return xio.ErrUnsupported
}

func (c *websocketConn) Context() context.Context {
	return c.ctx
}
