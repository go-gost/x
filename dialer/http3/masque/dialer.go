package masque

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/go-gost/core/dialer"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	registry.DialerRegistry().Register("h3-masque", NewDialer)
}

type masqueDialer struct {
	clients     map[string]*Client
	clientMutex sync.Mutex
	md          metadata
	options     dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &masqueDialer{
		clients: make(map[string]*Client),
		options: options,
	}
}

func (d *masqueDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

// Multiplex implements dialer.Multiplexer interface.
func (d *masqueDialer) Multiplex() bool {
	return true
}

func (d *masqueDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	d.clientMutex.Lock()
	defer d.clientMutex.Unlock()

	// Check if cached client is still alive
	client := d.clients[addr]
	if client != nil && client.IsClosed() {
		client.Close()
		delete(d.clients, addr)
		client = nil
	}

	if client == nil {
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

		dialFn := func(ctx context.Context, adr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}

			udpConn, err := options.Dialer.Dial(ctx, "udp", "")
			if err != nil {
				return nil, err
			}

			return quic.DialEarly(ctx, udpConn.(net.PacketConn), udpAddr, tlsCfg, cfg)
		}

		// Ensure TLS config has HTTP/3 ALPN
		tlsCfg := d.options.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		tlsCfg = tlsCfg.Clone()
		if len(tlsCfg.NextProtos) == 0 {
			tlsCfg.NextProtos = []string{http3.NextProtoH3}
		}
		if tlsCfg.ServerName == "" && host != "" {
			tlsCfg.ServerName = host
		}

		client = &Client{
			log:  d.options.Logger,
			host: host,
			addr: addr,
			dialer: dialFn,
			transport: &http3.Transport{
				TLSClientConfig: tlsCfg,
				EnableDatagrams: true,
				QUICConfig: &quic.Config{
					KeepAlivePeriod:      d.md.keepAlivePeriod,
					HandshakeIdleTimeout: d.md.handshakeTimeout,
					MaxIdleTimeout:       d.md.maxIdleTimeout,
					Versions: []quic.Version{
						quic.Version1,
						quic.Version2,
					},
					MaxIncomingStreams: int64(d.md.maxStreams),
					EnableDatagrams:    true,
				},
			},
		}
		d.clients[addr] = client
	}

	// Dial opens a request stream - if this fails, connection is dead
	conn, err := client.Dial(ctx, addr)
	if err != nil {
		// Stream opening failed - connection is dead, remove from cache
		d.options.Logger.Error(err)
		client.Close()
		delete(d.clients, addr)
		return nil, err
	}

	return conn, nil
}
