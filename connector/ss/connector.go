package ss

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/go-shadowsocks2/utils"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/ss"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("ss", NewConnector)
}

type ssConnector struct {
	client  core.TCPClient
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &ssConnector{
		options: options,
	}
}

func (c *ssConnector) Init(md md.Metadata) (err error) {
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

		c.client = core.NewTCPClient(clientConfig)
	}

	return
}

func (c *ssConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	switch network {
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
	rawaddr := bufpool.Get(512)
	defer bufpool.Put(rawaddr)

	n, err := addr.Encode(rawaddr)
	if err != nil {
		log.Error("encoding addr: ", err)
		return nil, err
	}

	if c.md.connectTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	target := socks.Addr(rawaddr[:n])
	_, padding, err := utils.GeneratePadding()
	if err != nil {
		return nil, err
	}
	conn, err = c.client.WrapConn(conn, target, padding, nil)
	if err != nil {
		return nil, err
	}

	var sc net.Conn
	if c.md.noDelay {
		err := conn.(core.TCPConn).ClientFirstWrite()
		if err != nil {
			return nil, err
		}
	}
	sc = ss.ShadowConn(conn, nil)

	return sc, nil
}
