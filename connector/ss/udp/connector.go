package ss

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/internal/util/ss"
	"github.com/go-gost/x/registry"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

func init() {
	registry.ConnectorRegistry().Register("ssu", NewConnector)
}

type ssuConnector struct {
	cipher  core.Cipher
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &ssuConnector{
		options: options,
	}
}

func (c *ssuConnector) Init(md md.Metadata) (err error) {
	if err = c.parseMetadata(md); err != nil {
		return
	}

	if c.options.Auth != nil {
		method := c.options.Auth.Username()
		password, _ := c.options.Auth.Password()
		c.cipher, err = ss.ShadowCipher(method, password, c.md.key)
	}

	return
}

func (c *ssuConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	switch network {
	case "udp", "udp4", "udp6":
	default:
		err := fmt.Errorf("network %s is unsupported", network)
		log.Error(err)
		return nil, err
	}

	if c.md.connectTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	taddr, _ := net.ResolveUDPAddr(network, address)
	if taddr == nil {
		taddr = &net.UDPAddr{}
	}

	pc, ok := conn.(net.PacketConn)
	if ok {
		if c.cipher != nil {
			pc = c.cipher.PacketConn(pc)
		}

		// standard UDP relay
		return ss.UDPClientConn(pc, conn.RemoteAddr(), taddr), nil
	}

	if c.cipher != nil {
		conn = ss.ShadowConn(c.cipher.StreamConn(conn), nil)
	}

	// UDP over TCP
	return relay.UDPTunClientConn(conn, taddr), nil
}
