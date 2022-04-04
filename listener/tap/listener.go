package tap

import (
	"net"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("tap", NewListener)
}

type tapListener struct {
	saddr   string
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
	return &tapListener{
		saddr:   options.Addr,
		logger:  options.Logger,
		options: options,
	}
}

func (l *tapListener) Init(md mdata.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	l.addr, err = net.ResolveUDPAddr("udp", l.saddr)
	if err != nil {
		return
	}

	ifce, ip, err := l.createTap()
	if err != nil {
		if ifce != nil {
			ifce.Close()
		}
		return
	}

	itf, err := net.InterfaceByName(ifce.Name())
	if err != nil {
		return
	}

	addrs, _ := itf.Addrs()
	l.logger.Infof("name: %s, mac: %s, mtu: %d, addrs: %s",
		itf.Name, itf.HardwareAddr, itf.MTU, addrs)

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

func (l *tapListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case <-l.closed:
	}

	return nil, listener.ErrClosed
}

func (l *tapListener) Addr() net.Addr {
	return l.addr
}

func (l *tapListener) Close() error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		close(l.closed)
	}
	return nil
}
