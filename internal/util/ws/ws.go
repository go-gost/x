package ws

import (
	"net"
	"sync"
	"time"

	xnet "github.com/go-gost/x/internal/net"
	"github.com/gorilla/websocket"
)

type WebsocketConn interface {
	net.Conn
	WriteMessage(int, []byte) error
	ReadMessage() (int, []byte, error)
	xnet.ClientAddr
}

type websocketConn struct {
	*websocket.Conn
	rb         []byte
	clientAddr net.Addr
	mux        sync.Mutex
}

func Conn(conn *websocket.Conn) WebsocketConn {
	return &websocketConn{
		Conn: conn,
	}
}

func ConnWithClientAddr(conn *websocket.Conn, clientAddr net.Addr) WebsocketConn {
	return &websocketConn{
		Conn:       conn,
		clientAddr: clientAddr,
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

func (c *websocketConn) ClientAddr() net.Addr {
	return c.clientAddr
}
