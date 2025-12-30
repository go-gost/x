package masque

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Client manages HTTP/3 connections for MASQUE proxying.
// It wraps a QUIC connection and HTTP/3 client, following the session pattern
// used by other gost dialers (ssh, quic, mws, etc.).
type Client struct {
	host       string
	addr       string
	transport  *http3.Transport
	quicConn   *quic.Conn
	clientConn *http3.ClientConn
	dialer     func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	log        logger.Logger
}

// IsClosed returns true if the underlying connection is closed.
// This follows the pattern used by other gost session wrappers.
func (c *Client) IsClosed() bool {
	if c.clientConn == nil {
		return true
	}
	select {
	case <-c.clientConn.Context().Done():
		return true
	default:
	}
	return false
}

// Close closes the client connection.
func (c *Client) Close() error {
	if c.quicConn != nil {
		return (*c.quicConn).CloseWithError(0, "closed")
	}
	return nil
}

// Dial establishes an HTTP/3 connection to the proxy server.
// It returns a MasqueConn that can be used by the MASQUE connector.
// Following the QUIC dialer pattern, this opens a request stream immediately
// to detect dead connections and allow cache invalidation.
func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Create connection if we don't have one (caller checks IsClosed first)
	if c.clientConn == nil {
		// Use the transport's Dial function to establish QUIC connection
		quicConn, err := c.dialer(ctx, addr, c.transport.TLSClientConfig, c.transport.QUICConfig)
		if err != nil {
			return nil, err
		}
		c.quicConn = quicConn

		// Create HTTP/3 client connection on top of QUIC
		c.clientConn = c.transport.NewClientConn(quicConn)
	}

	// Open request stream NOW (following QUIC dialer pattern).
	// This allows dead connection detection - if this fails, caller can invalidate cache.
	reqStream, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		// Connection is dead - clear our state so next dial creates fresh connection
		c.clientConn = nil
		c.quicConn = nil
		return nil, err
	}

	// Return a connection wrapper with pre-opened stream
	return &MasqueConn{
		clientConn: c.clientConn,
		reqStream:  reqStream,
		host:       c.host,
		log:        c.log,
	}, nil
}

// MasqueConn wraps an HTTP/3 client connection for use with the MASQUE connector.
// It implements net.Conn for compatibility with the gost connector interface,
// but the actual data transfer happens via datagrams through the pre-opened RequestStream.
type MasqueConn struct {
	clientConn *http3.ClientConn
	reqStream  *http3.RequestStream // Pre-opened stream for CONNECT-UDP
	host       string
	log        logger.Logger
}

// GetRequestStream returns the pre-opened HTTP/3 request stream.
// The connector uses this for the CONNECT-UDP handshake.
func (c *MasqueConn) GetRequestStream() *http3.RequestStream {
	return c.reqStream
}

// GetHost returns the proxy host.
func (c *MasqueConn) GetHost() string {
	return c.host
}

// Read implements net.Conn but is not used for MASQUE.
// The actual data transfer happens via datagrams.
func (c *MasqueConn) Read(b []byte) (n int, err error) {
	// This should not be called - datagrams are used for data transfer
	return 0, nil
}

// Write implements net.Conn but is not used for MASQUE.
// The actual data transfer happens via datagrams.
func (c *MasqueConn) Write(b []byte) (n int, err error) {
	// This should not be called - datagrams are used for data transfer
	return len(b), nil
}

// Close closes the connection.
func (c *MasqueConn) Close() error {
	// Don't close the underlying clientConn as it's shared/pooled
	return nil
}

// LocalAddr returns the local network address.
func (c *MasqueConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

// RemoteAddr returns the remote network address.
func (c *MasqueConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

// SetDeadline sets the read and write deadlines.
func (c *MasqueConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *MasqueConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *MasqueConn) SetWriteDeadline(t time.Time) error {
	return nil
}
