package masque

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	masque_dialer "github.com/go-gost/x/dialer/http3/masque"
	masque_util "github.com/go-gost/x/internal/util/masque"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("masque", NewConnector)
}

var (
	ErrInvalidConnection  = errors.New("masque: invalid connection type, expected MasqueConn")
	ErrConnectFailed      = errors.New("masque: CONNECT failed")
	ErrCapsuleRequired    = errors.New("masque: server did not confirm capsule-protocol")
	ErrUnsupportedNetwork = errors.New("masque: unsupported network type")
)

type masqueConnector struct {
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &masqueConnector{
		options: options,
	}
}

func (c *masqueConnector) Init(md md.Metadata) (err error) {
	return c.parseMetadata(md)
}

func (c *masqueConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})

	// Dispatch based on network type
	if strings.HasPrefix(network, "tcp") {
		return c.connectTCP(ctx, conn, address, log)
	}
	if strings.HasPrefix(network, "udp") {
		return c.connectUDP(ctx, conn, address, log)
	}

	log.Errorf("masque: unsupported network: %s", network)
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedNetwork, network)
}

func (c *masqueConnector) connectTCP(ctx context.Context, conn net.Conn, address string, log logger.Logger) (net.Conn, error) {
	log.Debugf("connect-tcp %s", address)

	// Get the MasqueConn from the dialer
	masqueConn, ok := conn.(*masque_dialer.MasqueConn)
	if !ok {
		log.Error(ErrInvalidConnection)
		return nil, ErrInvalidConnection
	}

	// Get pre-opened stream from dialer
	reqStream := masqueConn.GetRequestStream()
	proxyHost := masqueConn.GetHost()

	// Apply connect timeout to the actual stream
	if c.md.connectTimeout > 0 {
		reqStream.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer reqStream.SetDeadline(time.Time{})
	}

	// Ensure stream is closed on any error
	success := false
	defer func() {
		if !success {
			reqStream.Close()
		}
	}()

	// Create standard HTTP/3 CONNECT request (RFC 9114)
	// No :protocol pseudo-header for standard CONNECT
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{},
		Host:   address, // Target address goes in :authority
		Header: http.Header{},
		Proto:  "HTTP/3.0",
	}

	// Add proxy authentication if configured
	if c.options.Auth != nil {
		u := c.options.Auth.Username()
		p, _ := c.options.Auth.Password()
		auth := u + ":" + p
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", "Basic "+encoded)
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Tracef("CONNECT request: %s Host=%s ProxyHost=%s", req.Method, address, proxyHost)
	}
	log.Debugf("sending CONNECT request for %s", address)

	// Send request headers
	if err := reqStream.SendRequestHeader(req); err != nil {
		log.Error("masque: failed to send request:", err)
		return nil, err
	}

	// Read response
	resp, err := reqStream.ReadResponse()
	if err != nil {
		log.Error("masque: failed to read response:", err)
		return nil, err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Tracef("CONNECT response: %d %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("masque: proxy returned status %d", resp.StatusCode)
		return nil, fmt.Errorf("%w: status %d", ErrConnectFailed, resp.StatusCode)
	}

	log.Debugf("CONNECT established to %s", address)

	// Resolve target address
	raddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	// Create stream connection for TCP data transfer
	streamConn := masque_util.NewStreamConnFromRequestStream(reqStream, conn.LocalAddr(), raddr)

	success = true // Prevent defer from closing stream - streamConn now owns it
	return streamConn, nil
}

func (c *masqueConnector) connectUDP(ctx context.Context, conn net.Conn, address string, log logger.Logger) (net.Conn, error) {
	log.Debugf("connect-udp %s", address)

	// Get the MasqueConn from the dialer
	masqueConn, ok := conn.(*masque_dialer.MasqueConn)
	if !ok {
		log.Error(ErrInvalidConnection)
		return nil, ErrInvalidConnection
	}

	// Get pre-opened stream from dialer (stream opening happens there for dead connection detection)
	reqStream := masqueConn.GetRequestStream()
	proxyHost := masqueConn.GetHost()

	// Apply connect timeout to the actual stream
	if c.md.connectTimeout > 0 {
		reqStream.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer reqStream.SetDeadline(time.Time{})
	}

	// Ensure stream is closed on any error
	success := false
	defer func() {
		if !success {
			reqStream.Close()
		}
	}()

	// Build CONNECT-UDP path
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid address %s: %w", address, err)
	}

	path := masque_util.BuildMasquePath(host, mustAtoi(port))

	// Create CONNECT-UDP request
	// For Extended CONNECT (RFC 9220), set Proto to the :protocol value
	// quic-go translates req.Proto to the :protocol pseudo-header
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Path: path},
		Host:   proxyHost,
		Header: http.Header{
			"Capsule-Protocol": []string{"?1"},
		},
		Proto:      "connect-udp", // This becomes the :protocol pseudo-header
		ProtoMajor: 3,
	}

	// Add proxy authentication if configured
	// Use Proxy-Authorization header (not Authorization) for proxy auth
	if c.options.Auth != nil {
		u := c.options.Auth.Username()
		p, _ := c.options.Auth.Password()
		auth := u + ":" + p
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", "Basic "+encoded)
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Tracef("CONNECT-UDP request: %s %s Host=%s", req.Method, path, proxyHost)
	}
	log.Debugf("sending CONNECT-UDP request to %s", path)

	// Send request headers
	if err := reqStream.SendRequestHeader(req); err != nil {
		log.Error("masque: failed to send request:", err)
		return nil, err
	}

	// Read response
	resp, err := reqStream.ReadResponse()
	if err != nil {
		log.Error("masque: failed to read response:", err)
		return nil, err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Tracef("CONNECT-UDP response: %d %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("masque: proxy returned status %d", resp.StatusCode)
		return nil, fmt.Errorf("%w: status %d", ErrConnectFailed, resp.StatusCode)
	}

	if resp.Header.Get("Capsule-Protocol") != "?1" {
		log.Error(ErrCapsuleRequired)
		return nil, ErrCapsuleRequired
	}

	log.Debugf("CONNECT-UDP established to %s", address)

	// Get the underlying HTTP/3 stream for datagrams
	stream := reqStream

	// Resolve target address
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	// Create datagram connection wrapping the request stream
	datagramConn := masque_util.NewDatagramConnFromRequestStream(stream, conn.LocalAddr(), raddr)

	success = true // Prevent defer from closing stream - datagramConn now owns it
	return datagramConn, nil
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
