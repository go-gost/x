package ws

import (
	"context"
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
	rb  []byte
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
	if len(c.rb) == 0 {
		_, c.rb, err = c.Conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
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

func (c *websocketConn) Close() error {
	// gorilla/websocket's Conn.Close() closes the underlying net.Conn without
	// sending a close control frame. That often shows up as `close 1006
	// (abnormal closure): unexpected EOF` on the peer.
	//
	// Best-effort: send a normal close frame, then close the connection.
	c.mux.Lock()
	deadline := time.Now().Add(2 * time.Second)
	_ = c.Conn.SetWriteDeadline(deadline)
	_ = c.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		deadline,
	)
	_ = c.Conn.SetWriteDeadline(time.Time{})
	c.mux.Unlock()

	return c.Conn.Close()
}

func (c *websocketConn) CloseRead() error {
	// WebSocket is message-oriented; doing a TCP half-close on the underlying
	// connection can cause abnormal closures (e.g. close 1006) for the peer.
	// We intentionally do not expose a half-close read.
	return xio.ErrUnsupported
}

func (c *websocketConn) CloseWrite() error {
	// WebSocket does not support TCP half-close semantics. To signal EOF to the
	// peer, send a WebSocket close control frame.
	c.mux.Lock()
	defer c.mux.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	_ = c.Conn.SetWriteDeadline(deadline)
	err := c.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		deadline,
	)
	_ = c.Conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *websocketConn) Context() context.Context {
	return c.ctx
}
