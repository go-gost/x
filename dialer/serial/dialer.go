package serial

import (
	"context"
	"net"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	serial_util "github.com/go-gost/x/internal/util/serial"
	"github.com/go-gost/x/registry"
	goserial "github.com/tarm/serial"
)

func init() {
	registry.DialerRegistry().Register("serial", NewDialer)
}

type serialDialer struct {
	md     metadata
	logger logger.Logger
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}

	return &serialDialer{
		logger: options.Logger,
	}
}

func (d *serialDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *serialDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	cfg := serial_util.ParseConfigFromAddr(addr)
	port, err := goserial.OpenPort(cfg)
	if err != nil {
		return nil, err
	}

	return serial_util.NewConn(port, &serial_util.Addr{Port: cfg.Name}, nil), nil
}
