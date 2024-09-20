package serial

import (
	"context"
	"net"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("serial", NewConnector)
}

type serialConnector struct {
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &serialConnector{
		options: options,
	}
}

func (c *serialConnector) Init(md md.Metadata) (err error) {
	return nil
}

func (c *serialConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	return conn, nil
}
