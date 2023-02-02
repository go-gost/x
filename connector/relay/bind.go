package relay

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/go-gost/core/common/net/udp"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	relay_util "github.com/go-gost/x/internal/util/relay"
)

// Bind implements connector.Binder.
func (c *relayConnector) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	if !c.md.tunnelID.IsZero() {
		return c.bindTunnel(ctx, conn, network, c.options.Logger)
	}

	log := c.options.Logger.WithFields(map[string]any{
		"network": network,
		"address": address,
	})
	log.Debugf("bind on %s/%s", address, network)

	options := connector.BindOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.bindTCP(ctx, conn, network, address, log)
	case "udp", "udp4", "udp6":
		return c.bindUDP(ctx, conn, network, address, &options, log)
	default:
		err := fmt.Errorf("network %s is unsupported", network)
		log.Error(err)
		return nil, err
	}
}

func (c *relayConnector) bindTunnel(ctx context.Context, conn net.Conn, network string, log logger.Logger) (net.Listener, error) {
	addr, cid, err := c.initTunnel(conn, network)
	if err != nil {
		return nil, err
	}
	log.Debugf("create tunnel %s connector %s/%s OK", c.md.tunnelID.String(), cid, network)

	session, err := mux.ServerSession(conn)
	if err != nil {
		return nil, err
	}

	return &bindListener{
		network: network,
		addr:    addr,
		session: session,
		logger:  log,
	}, nil
}

func (c *relayConnector) initTunnel(conn net.Conn, network string) (addr net.Addr, cid relay.ConnectorID, err error) {
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdBind,
	}

	if network == "udp" {
		req.Cmd |= relay.FUDP
	}

	if c.options.Auth != nil {
		pwd, _ := c.options.Auth.Password()
		req.Features = append(req.Features, &relay.UserAuthFeature{
			Username: c.options.Auth.Username(),
			Password: pwd,
		})
	}

	req.Features = append(req.Features, &relay.TunnelFeature{
		ID: c.md.tunnelID.ID(),
	})
	if _, err = req.WriteTo(conn); err != nil {
		return
	}

	// first reply, bind status
	resp := relay.Response{}
	if _, err = resp.ReadFrom(conn); err != nil {
		return
	}

	if resp.Status != relay.StatusOK {
		err = fmt.Errorf("%d: create tunnel %s failed", resp.Status, c.md.tunnelID.String())
		return
	}

	for _, f := range resp.Features {
		switch f.Type() {
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				addr, err = net.ResolveTCPAddr("tcp", net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port))))
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				cid = relay.NewConnectorID(feature.ID[:])
			}
		}
	}

	return
}

func (c *relayConnector) bindTCP(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) (net.Listener, error) {
	laddr, err := c.bind(conn, relay.CmdBind, network, address)
	if err != nil {
		return nil, err
	}
	log.Debugf("bind on %s/%s OK", laddr, laddr.Network())

	session, err := mux.ServerSession(conn)
	if err != nil {
		return nil, err
	}

	return &bindListener{
		addr:    laddr,
		session: session,
		logger:  log,
	}, nil
}

func (c *relayConnector) bindUDP(ctx context.Context, conn net.Conn, network, address string, opts *connector.BindOptions, log logger.Logger) (net.Listener, error) {
	laddr, err := c.bind(conn, relay.FUDP|relay.CmdBind, network, address)
	if err != nil {
		return nil, err
	}
	log.Debugf("bind on %s/%s OK", laddr, laddr.Network())

	ln := udp.NewListener(
		relay_util.UDPTunClientPacketConn(conn),
		&udp.ListenConfig{
			Addr:           laddr,
			Backlog:        opts.Backlog,
			ReadQueueSize:  opts.UDPDataQueueSize,
			ReadBufferSize: opts.UDPDataBufferSize,
			TTL:            opts.UDPConnTTL,
			KeepAlive:      true,
			Logger:         log,
		})

	return ln, nil
}

func (c *relayConnector) bind(conn net.Conn, cmd relay.CmdType, network, address string) (net.Addr, error) {
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     cmd,
	}

	if c.options.Auth != nil {
		pwd, _ := c.options.Auth.Password()
		req.Features = append(req.Features, &relay.UserAuthFeature{
			Username: c.options.Auth.Username(),
			Password: pwd,
		})
	}
	fa := &relay.AddrFeature{}
	fa.ParseFrom(address)
	req.Features = append(req.Features, fa)
	if _, err := req.WriteTo(conn); err != nil {
		return nil, err
	}

	// first reply, bind status
	resp := relay.Response{}
	if _, err := resp.ReadFrom(conn); err != nil {
		return nil, err
	}

	if resp.Status != relay.StatusOK {
		return nil, fmt.Errorf("bind on %s/%s failed", address, network)
	}

	var addr string
	for _, f := range resp.Features {
		if f.Type() == relay.FeatureAddr {
			if fa, ok := f.(*relay.AddrFeature); ok {
				addr = net.JoinHostPort(fa.Host, strconv.Itoa(int(fa.Port)))
			}
		}
	}

	var baddr net.Addr
	var err error
	switch network {
	case "tcp", "tcp4", "tcp6":
		baddr, err = net.ResolveTCPAddr(network, addr)
	case "udp", "udp4", "udp6":
		baddr, err = net.ResolveUDPAddr(network, addr)
	default:
		err = fmt.Errorf("unknown network %s", network)
	}
	if err != nil {
		return nil, err
	}

	return baddr, nil
}
