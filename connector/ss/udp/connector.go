package ss

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/go-shadowsocks2/utils"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/internal/util/ss"
	ssnone "github.com/go-gost/x/internal/util/ss/none"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("ssu", NewConnector)
}

type ssuConnector struct {
	clientCfg core.ClientConfig
	tcpClient core.TCPClient
	md        metadata
	options   connector.Options
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

	if c.options.Auth == nil {
		return errors.New("ss: auth is required")
	}

	method := c.options.Auth.Username()
	password, _ := c.options.Auth.Password()

	if strings.EqualFold(method, "none") || strings.EqualFold(method, "dummy") {
		c.clientCfg = core.ClientConfig{Cipher: ssnone.Cipher, UDPTimeout: time.Minute}
		c.tcpClient = core.NewTCPClient(core.ClientConfig{Cipher: ssnone.Cipher})
		return
	}

	clientConfig, err := utils.NewClientConfig(method, password)
	if err != nil {
		return err
	}
	clientConfig.UDPTimeout = time.Minute

	c.clientCfg = clientConfig
	c.tcpClient = core.NewTCPClient(clientConfig)

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
	serverAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("ss: parse remote addr %q: %w", conn.RemoteAddr().String(), err)
	}
	clientCfg := c.clientCfg
	clientCfg.ServerAddr = serverAddr
	client := core.NewUDPClient(clientCfg)
	if err := client.Init(); err != nil {
		return nil, err
	}

	pc, ok := conn.(net.PacketConn)
	if ok {
		// standard UDP relay
		return ss.UDPClientConn(pc, taddr, &client), nil
	}

	target := socks.ParseAddr(taddr.String())
	conn, err = c.tcpClient.WrapConn(conn, target)
	if err != nil {
		return nil, err
	}

	// UDP over TCP
	return relay.UDPTunClientConn(conn, taddr), nil
}
