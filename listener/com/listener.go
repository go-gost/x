package com

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	"github.com/go-gost/x/registry"
	goserial "github.com/tarm/serial"
)

func init() {
	registry.ListenerRegistry().Register("com", NewListener)
}

type comListener struct {
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
		options.Addr = defaultPort
	}

	return &comListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *comListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	l.addr = &comAddr{port: l.options.Addr}

	l.cqueue = make(chan net.Conn)
	l.closed = make(chan struct{})

	go l.listenLoop()

	return
}

func (l *comListener) Accept() (conn net.Conn, err error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case <-l.closed:
	}

	return nil, listener.ErrClosed
}

func (l *comListener) Addr() net.Addr {
	return l.addr
}

func (l *comListener) Close() error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		close(l.closed)
	}
	return nil
}

func (l *comListener) listenLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		err := func() error {
			port, err := goserial.OpenPort(&goserial.Config{
				Name:        l.options.Addr,
				Baud:        l.md.baudRate,
				Parity:      parseParity(l.md.parity),
				ReadTimeout: l.md.timeout,
			})
			if err != nil {
				return err
			}

			var c net.Conn
			c = &conn{
				port:   port,
				laddr:  l.addr,
				raddr:  l.addr,
				cancel: cancel,
			}
			c = metrics.WrapConn(l.options.Service, c)
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

func parseParity(s string) goserial.Parity {
	switch strings.ToLower(s) {
	case "o", "odd":
		return goserial.ParityOdd
	case "e", "even":
		return goserial.ParityEven
	case "m", "mark":
		return goserial.ParityMark
	case "s", "space":
		return goserial.ParitySpace
	default:
		return goserial.ParityNone
	}
}
