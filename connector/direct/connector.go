// Package direct implements a direct (transparent) connector that establishes
// connections to destination addresses using the dialer provided via connect
// options. It also supports a "reject" action that returns a dead connection
// (reads return io.EOF, writes return io.ErrClosedPipe) without dialing.
package direct

import (
	"context"
	"errors"
	"net"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("direct", NewConnector)
	registry.ConnectorRegistry().Register("virtual", NewConnector)
}

type directConnector struct {
	md      metadata
	options connector.Options
}

// NewConnector creates a direct connector with the given options.
func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &directConnector{
		options: options,
	}
}

func (c *directConnector) Init(md md.Metadata) (err error) {
	return c.parseMetadata(md)
}

func (c *directConnector) Connect(ctx context.Context, _ net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	var cOpts connector.ConnectOptions
	for _, opt := range opts {
		opt(&cOpts)
	}

	if c.md.action == "reject" {
		return &conn{}, nil
	}

	if cOpts.Dialer == nil {
		return nil, errors.New("direct: missing dialer in connect options")
	}

	conn, err := cOpts.Dialer.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if c.options.Logger != nil {
		var localAddr, remoteAddr string
		if addr := conn.LocalAddr(); addr != nil {
			localAddr = addr.String()
		}
		if addr := conn.RemoteAddr(); addr != nil {
			remoteAddr = addr.String()
		}

		log := c.options.Logger.WithFields(map[string]any{
			"remote":  remoteAddr,
			"local":   localAddr,
			"network": network,
			"address": address,
			"sid":     string(ctxvalue.SidFromContext(ctx)),
		})
		log.Debugf("connect %s/%s", address, network)
	}

	return conn, nil
}
