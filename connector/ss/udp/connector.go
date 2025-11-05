package ss

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/go-shadowsocks2/utils"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/internal/util/ss"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("ssu", NewConnector)
}

type ssuConnector struct {
	client     core.UDPClient
	tcpClient  core.TCPClient
	md         metadata
	options    connector.Options
	sessionMap sync.Map
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
		clientConfig, err := utils.NewClientConfig(method, password)
		if err != nil {
			return nil
		}
		c.client = core.NewUDPClient(clientConfig, 60)
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
		// standard UDP relay
		return ss.UDPClientConn(pc, conn.RemoteAddr(), taddr, c.md.udpBufferSize, &c.client, &c.sessionMap), nil
	}

	_, padding, err := utils.GeneratePadding()
	if err != nil {
		return nil, err
	}

	target := socks.ParseAddr(taddr.String())
	conn, err = c.tcpClient.WrapConn(conn, target, padding, nil)
	if err != nil {
		return nil, err
	}

	// UDP over TCP
	return relay.UDPTunClientConn(conn, taddr), nil
}
