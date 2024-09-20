package relay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	relay_util "github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("relay", NewConnector)
}

type relayConnector struct {
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &relayConnector{
		options: options,
	}
}

func (c *relayConnector) Init(md md.Metadata) (err error) {
	return c.parseMetadata(md)
}

func (c *relayConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
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

	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}

	switch network {
	case "udp", "udp4", "udp6":
		req.Cmd |= relay.FUDP
		req.Features = append(req.Features, &relay.NetworkFeature{
			Network: relay.NetworkUDP,
		})

		// UDP association
		if address == "" {
			baddr, err := c.bind(conn, relay.FUDP|relay.CmdBind, network, address)
			if err != nil {
				return nil, err
			}
			log.Debugf("associate on %s OK", baddr)

			return relay_util.UDPTunClientConn(conn, nil), nil
		}

	case "unix":
		req.Features = append(req.Features, &relay.NetworkFeature{
			Network: relay.NetworkUnix,
		})
	case "serial":
		req.Features = append(req.Features, &relay.NetworkFeature{
			Network: relay.NetworkSerial,
		})
	}

	if c.options.Auth != nil {
		pwd, _ := c.options.Auth.Password()
		req.Features = append(req.Features, &relay.UserAuthFeature{
			Username: c.options.Auth.Username(),
			Password: pwd,
		})
	}

	if address != "" {
		af := &relay.AddrFeature{}
		if err := af.ParseFrom(address); err != nil {
			return nil, err
		}
		req.Features = append(req.Features, af)
	}

	if c.md.noDelay {
		if _, err := req.WriteTo(conn); err != nil {
			return nil, err
		}
		// drain the response
		if err := readResponse(conn); err != nil {
			return nil, err
		}
	}

	switch network {
	case "tcp", "tcp4", "tcp6", "unix", "serial":
		if !c.md.noDelay {
			cc := &tcpConn{
				Conn: conn,
				wbuf: &bytes.Buffer{},
			}
			if _, err := req.WriteTo(cc.wbuf); err != nil {
				return nil, err
			}
			conn = cc
		}
	case "udp", "udp4", "udp6":
		cc := &udpConn{
			Conn: conn,
		}
		if !c.md.noDelay {
			cc.wbuf = &bytes.Buffer{}
			if _, err := req.WriteTo(cc.wbuf); err != nil {
				return nil, err
			}
		}
		conn = cc
	default:
		err := fmt.Errorf("network %s is unsupported", network)
		log.Error(err)
		return nil, err
	}

	return conn, nil
}
