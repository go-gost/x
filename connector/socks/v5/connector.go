package v5

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/socks"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("socks5", NewConnector)
	registry.ConnectorRegistry().Register("socks", NewConnector)
}

type socks5Connector struct {
	selector gosocks5.Selector
	md       metadata
	options  connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &socks5Connector{
		options: options,
	}
}

func (c *socks5Connector) Init(md md.Metadata) (err error) {
	if err = c.parseMetadata(md); err != nil {
		return
	}

	selector := &clientSelector{
		methods: []uint8{
			gosocks5.MethodNoAuth,
		},
		User:      c.options.Auth,
		TLSConfig: c.options.TLSConfig,
		logger:    c.options.Logger,
	}
	if selector.User != nil {
		selector.methods = append(selector.methods, gosocks5.MethodUserPass)
	}
	if !c.md.noTLS {
		selector.methods = append(selector.methods, socks.MethodTLS)
		if selector.TLSConfig == nil {
			selector.TLSConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
		if selector.User != nil {
			selector.methods = append(selector.methods, socks.MethodTLSAuth)
		}
	}
	c.selector = selector

	return
}

// Handshake implements connector.Handshaker.
func (c *socks5Connector) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	if c.md.connectTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	cc := gosocks5.ClientConn(conn, c.selector)
	if err := cc.Handleshake(); err != nil {
		log.Error(err)
		return nil, err
	}

	return cc, nil
}

func (c *socks5Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	if c.md.connectTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	var cOpts connector.ConnectOptions
	for _, opt := range opts {
		opt(&cOpts)
	}

	switch network {
	case "udp", "udp4", "udp6":
		return c.connectUDP(ctx, conn, network, address, log, &cOpts)
	case "tcp", "tcp4", "tcp6":
		if _, ok := conn.(net.PacketConn); ok {
			err := fmt.Errorf("tcp over udp is unsupported")
			log.Error(err)
			return nil, err
		}
	default:
		err := fmt.Errorf("network %s is unsupported", network)
		log.Error(err)
		return nil, err
	}

	addr := gosocks5.Addr{}
	if err := addr.ParseFrom(address); err != nil {
		log.Error(err)
		return nil, err
	}
	if addr.Host == "" {
		addr.Type = gosocks5.AddrIPv4
		addr.Host = "127.0.0.1"
	}

	req := gosocks5.NewRequest(gosocks5.CmdConnect, &addr)
	log.Trace(req)
	if err := req.Write(conn); err != nil {
		log.Error(err)
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	log.Trace(reply)

	if reply.Rep != gosocks5.Succeeded {
		err = errors.New("host unreachable")
		log.Error(err)
		return nil, err
	}

	return conn, nil
}

func (c *socks5Connector) connectUDP(ctx context.Context, conn net.Conn, network, address string, log logger.Logger, opts *connector.ConnectOptions) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if c.md.relay == "udp" {
		return c.relayUDP(ctx, conn, addr, log, opts)
	}

	req := gosocks5.NewRequest(socks.CmdUDPTun, nil)
	log.Trace(req)
	if err := req.Write(conn); err != nil {
		log.Error(err)
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	log.Trace(reply)

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("get socks5 UDP tunnel failure")
	}

	return socks.UDPTunClientConn(conn, addr), nil
}

func (c *socks5Connector) relayUDP(ctx context.Context, conn net.Conn, addr net.Addr, log logger.Logger, opts *connector.ConnectOptions) (net.Conn, error) {
	req := gosocks5.NewRequest(gosocks5.CmdUdp, nil)
	log.Trace(req)
	if err := req.Write(conn); err != nil {
		log.Error(err)
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	log.Trace(reply)

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("get socks5 UDP tunnel failure")
	}

	log.Debugf("bind on: %v", reply.Addr)

	cc, err := opts.Dialer.Dial(ctx, "udp", reply.Addr.String())
	if err != nil {
		c.options.Logger.Error(err)
		return nil, err
	}
	log.Debugf("%s <- %s -> %s", cc.LocalAddr(), cc.RemoteAddr(), addr)

	if c.md.udpTimeout > 0 {
		cc.SetReadDeadline(time.Now().Add(c.md.udpTimeout))
	}

	return &udpRelayConn{
		udpConn:    cc.(*net.UDPConn),
		tcpConn:    conn,
		taddr:      addr,
		bufferSize: c.md.udpBufferSize,
		logger:     log,
	}, nil
}
