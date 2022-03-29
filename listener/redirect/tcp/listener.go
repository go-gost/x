package tcp

import (
	"context"
	"net"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	"github.com/go-gost/core/registry"
)

func init() {
	registry.ListenerRegistry().Register("red", NewListener)
	registry.ListenerRegistry().Register("redir", NewListener)
	registry.ListenerRegistry().Register("redirect", NewListener)
}

type redirectListener struct {
	ln      net.Listener
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &redirectListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *redirectListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	lc := net.ListenConfig{}
	if l.md.tproxy {
		lc.Control = l.control
	}
	ln, err := lc.Listen(context.Background(), "tcp", l.options.Addr)
	if err != nil {
		return err
	}

	l.ln = metrics.WrapListener(l.options.Service, ln)
	return
}

func (l *redirectListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *redirectListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *redirectListener) Close() error {
	return l.ln.Close()
}
