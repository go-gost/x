package tun

import (
	"net"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("tun", NewListener)
}

type tunListener struct {
	addr    net.Addr
	cqueue  chan net.Conn
	closed  chan struct{}
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tunListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *tunListener) Init(md mdata.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "udp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "udp4"
	}
	l.addr, err = net.ResolveUDPAddr(network, l.options.Addr)
	if err != nil {
		return
	}

	ifce, name, ip, err := l.createTun()
	if err != nil {
		if ifce != nil {
			ifce.Close()
		}
		return
	}

	itf, err := net.InterfaceByName(name)
	if err != nil {
		return
	}

	addrs, _ := itf.Addrs()
	l.logger.Infof("name: %s, net: %s, mtu: %d, addrs: %s",
		itf.Name, ip, itf.MTU, addrs)

	l.cqueue = make(chan net.Conn, 1)
	l.closed = make(chan struct{})

	var c net.Conn
	c = &conn{
		ifce:  ifce,
		laddr: l.addr,
		raddr: &net.IPAddr{IP: ip},
	}
	c = metrics.WrapConn(l.options.Service, c)
	c = withMetadata(mdx.NewMetadata(map[string]any{
		"config": l.md.config,
	}), c)

	l.cqueue <- c

	return
}

func (l *tunListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case <-l.closed:
	}

	return nil, listener.ErrClosed
}

func (l *tunListener) Addr() net.Addr {
	return l.addr
}

func (l *tunListener) Close() error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		close(l.closed)
	}
	return nil
}
