package http2

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	net_dialer "github.com/go-gost/x/internal/net/dialer"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("http2", NewDialer)
}

type http2Dialer struct {
	clients     map[string]*http.Client
	clientMutex sync.Mutex
	logger      logger.Logger
	md          metadata
	options     dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &http2Dialer{
		clients: make(map[string]*http.Client),
		logger:  options.Logger,
		options: options,
	}
}

func (d *http2Dialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	return nil
}

// Multiplex implements dialer.Multiplexer interface.
func (d *http2Dialer) Multiplex() bool {
	return true
}

func (d *http2Dialer) Dial(ctx context.Context, address string, opts ...dialer.DialOption) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		d.logger.Error(err)
		return nil, err
	}

	d.clientMutex.Lock()
	defer d.clientMutex.Unlock()

	client, ok := d.clients[address]
	if !ok {
		options := dialer.DialOptions{}
		for _, opt := range opts {
			opt(&options)
		}

		{
			// Check whether the connection is established properly
			netd := options.Dialer
			if netd == nil {
				netd = net_dialer.DefaultNetDialer
			}
			conn, err := netd.Dial(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			conn.Close()
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: d.options.TLSConfig,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					netd := options.Dialer
					if netd == nil {
						netd = net_dialer.DefaultNetDialer
					}
					return netd.Dial(ctx, network, addr)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          16,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   30 * time.Second,
				ExpectContinueTimeout: 15 * time.Second,
			},
		}
		d.clients[address] = client
	}

	var c net.Conn = &conn{
		localAddr:  &net.TCPAddr{},
		remoteAddr: raddr,
		onClose: func() {
			d.clientMutex.Lock()
			defer d.clientMutex.Unlock()
			delete(d.clients, address)
		},
		md: mdx.NewMetadata(map[string]any{"client": client}),
	}

	return c, nil
}
