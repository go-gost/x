package pht

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	md "github.com/go-gost/core/metadata"
	pht_util "github.com/go-gost/x/internal/util/pht"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("pht", NewDialer)
	registry.DialerRegistry().Register("phts", NewTLSDialer)
}

type phtDialer struct {
	clients     map[string]*pht_util.Client
	clientMutex sync.Mutex
	tlsEnabled  bool
	md          metadata
	options     dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &phtDialer{
		clients: make(map[string]*pht_util.Client),
		options: options,
	}
}

func NewTLSDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &phtDialer{
		tlsEnabled: true,
		clients:    make(map[string]*pht_util.Client),
		options:    options,
	}
}

func (d *phtDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	if !d.tlsEnabled {
		return nil
	}
	return d.md.ech.Init(d.options.Logger, d.options.TLSConfig)
}

// Multiplex implements dialer.Multiplexer interface.
// NOTE: PHT is not a real multiplexed tunnel.
func (d *phtDialer) Multiplex() bool {
	return true
}

func (d *phtDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	d.clientMutex.Lock()
	defer d.clientMutex.Unlock()

	client, ok := d.clients[addr]
	if !ok {
		var options dialer.DialOptions
		for _, opt := range opts {
			opt(&options)
		}

		host := d.md.host
		if host == "" {
			host = options.Host
		}
		if h, _, _ := net.SplitHostPort(host); h != "" {
			host = h
		}

		tr := &http.Transport{
			// Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, adr string) (net.Conn, error) {
				return options.Dialer.Dial(ctx, network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		if d.tlsEnabled {
			serverName := host
			if d.options.TLSConfig != nil && d.options.TLSConfig.ServerName != "" {
				serverName = d.options.TLSConfig.ServerName
			}
			tlsCfg, err := d.md.ech.Apply(ctx, d.options.TLSConfig, serverName)
			if err != nil {
				return nil, err
			}
			tr.TLSClientConfig = tlsCfg
		}

		client = &pht_util.Client{
			Host: host,
			Client: &http.Client{
				// Timeout:   60 * time.Second,
				Transport: tr,
			},
			PushPath:   d.md.pushPath,
			PullPath:   d.md.pullPath,
			TLSEnabled: d.tlsEnabled,
			Header:     d.md.header,
			Logger:     d.options.Logger,
		}
		d.clients[addr] = client
	}

	ret, err := client.Dial(ctx, addr)
	if err != nil {
		sn := addr
		if h, _, err2 := net.SplitHostPort(addr); err2 == nil {
			sn = h
		}
		if d.options.TLSConfig != nil && d.options.TLSConfig.ServerName != "" {
			sn = d.options.TLSConfig.ServerName
		}
		if rerr := d.md.ech.OnDialError(ctx, err, sn); rerr != nil {
			delete(d.clients, addr)
			return nil, rerr
		}
		return nil, err
	}
	return ret, nil
}
