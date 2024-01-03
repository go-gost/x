package serial

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	serial "github.com/go-gost/x/internal/util/serial"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
	stats "github.com/go-gost/x/stats/wrapper"
)

func init() {
	registry.ListenerRegistry().Register("serial", NewListener)
}

type serialListener struct {
	cqueue  chan net.Conn
	closed  chan struct{}
	addr    net.Addr
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	if options.Addr == "" {
		options.Addr = serial.DefaultPort
	}

	return &serialListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *serialListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	l.addr = &serial.Addr{Port: l.options.Addr}

	l.cqueue = make(chan net.Conn)
	l.closed = make(chan struct{})

	go l.listenLoop()

	return
}

func (l *serialListener) Accept() (conn net.Conn, err error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case <-l.closed:
	}

	return nil, listener.ErrClosed
}

func (l *serialListener) Addr() net.Addr {
	return l.addr
}

func (l *serialListener) Close() error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		close(l.closed)
	}
	return nil
}

func (l *serialListener) listenLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		err := func() error {
			cfg := serial.ParseConfigFromAddr(l.options.Addr)
			cfg.ReadTimeout = l.md.timeout
			port, err := serial.OpenPort(cfg)
			if err != nil {
				return err
			}

			c := serial.NewConn(port, l.addr, cancel)
			c = metrics.WrapConn(l.options.Service, c)
			c = stats.WrapConn(c, l.options.Stats)
			c = limiter.WrapConn(l.options.TrafficLimiter, c)

			l.cqueue <- c

			return nil
		}()
		if err != nil {
			l.logger.Error(err)
			cancel()
		}

		select {
		case <-ctx.Done():
		case <-l.closed:
			return
		}

		time.Sleep(time.Second)
	}
}
