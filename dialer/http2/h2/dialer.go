package h2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/net/httptunnel"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/registry"
	"golang.org/x/net/http2"
)

func init() {
	registry.DialerRegistry().Register("h2", NewTLSDialer)
	registry.DialerRegistry().Register("h2c", NewDialer)
}

type h2Dialer struct {
	clients     map[string]*http.Client
	clientMutex sync.Mutex
	h2c         bool
	logger      logger.Logger
	md          metadata
	options     dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &h2Dialer{
		h2c:     true,
		clients: make(map[string]*http.Client),
		logger:  options.Logger,
		options: options,
	}
}

func NewTLSDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &h2Dialer{
		clients: make(map[string]*http.Client),
		logger:  options.Logger,
		options: options,
	}
}

func (d *h2Dialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	if d.h2c {
		return nil
	}
	return d.md.ech.Init(d.logger, d.options.TLSConfig)
}

// Multiplex implements dialer.Multiplexer interface.
func (d *h2Dialer) Multiplex() bool {
	return true
}

func (d *h2Dialer) Dial(ctx context.Context, address string, opts ...dialer.DialOption) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		d.logger.Error(err)
		return nil, err
	}

	d.clientMutex.Lock()

	client, ok := d.clients[address]
	if !ok {
		options := &dialer.DialOptions{}
		for _, opt := range opts {
			opt(options)
		}

		client = &http.Client{
			// A tunnel request carries its data in its body, so a followed
			// redirect would return a connection with a dead write side.
			// Report the redirect as a failed attempt instead.
			CheckRedirect: httptunnel.NoRedirect,
		}
		if d.h2c {
			client.Transport = &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					conn, err := options.Dialer.Dial(ctx, network, addr)
					if err != nil {
						return nil, err
					}

					conn = proxyproto.WrapClientConn(
						d.options.ProxyProtocol,
						xctx.SrcAddrFromContext(ctx),
						xctx.DstAddrFromContext(ctx),
						conn)

					return conn, nil
				},
			}
		} else {
			serverName := d.md.host
			if serverName == "" {
				if h, _, err := net.SplitHostPort(address); err == nil {
					serverName = h
				} else {
					serverName = address
				}
			}
			tlsCfg, err := d.md.ech.Apply(ctx, d.options.TLSConfig, serverName)
			if err != nil {
				d.clientMutex.Unlock()
				return nil, err
			}
			client.Transport = &http.Transport{
				TLSClientConfig: tlsCfg,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, err := options.Dialer.Dial(ctx, network, addr)
					if err != nil {
						return nil, err
					}

					conn = proxyproto.WrapClientConn(
						d.options.ProxyProtocol,
						xctx.SrcAddrFromContext(ctx),
						xctx.DstAddrFromContext(ctx),
						conn)

					return conn, nil
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}

		d.clients[address] = client
	}
	d.clientMutex.Unlock()

	host := d.md.host
	if host == "" {
		host = address
	}

	scheme := "https"
	if d.h2c {
		scheme = "http"
	}
	// The request body is the client-to-server half of the tunnel. Nothing is
	// written to it before Dial returns, so when the transport retries the
	// request on another connection (the server sent GOAWAY, or the
	// connection broke, before this stream was opened), a fresh pipe is an
	// exact replacement. Without GetBody the retry reuses the body the first
	// attempt already closed (golang/go#82177).
	body := httptunnel.NewBody()
	req := &http.Request{
		Method:  http.MethodConnect,
		URL:     &url.URL{Scheme: scheme, Host: host},
		Header:  d.md.header,
		Body:    body.Reader(),
		GetBody: body.GetBody,
		Host:    host,
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if d.md.path != "" {
		req.Method = http.MethodGet
		req.URL.Path = d.md.path
	}

	if d.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		d.logger.Trace(string(dump))
	}

	resp, err := client.Do(req.WithContext(context.WithoutCancel(ctx)))
	if err != nil {
		body.CloseWithError(err)
		if !d.h2c {
			serverName := d.md.host
			if serverName == "" {
				if h, _, err2 := net.SplitHostPort(address); err2 == nil {
					serverName = h
				} else {
					serverName = address
				}
			}
			if rerr := d.md.ech.OnDialError(ctx, err, serverName); rerr != nil {
				d.clientMutex.Lock()
				delete(d.clients, address)
				d.clientMutex.Unlock()
				return nil, rerr
			}
		}
		return nil, err
	}

	if d.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		d.logger.Trace(string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err := errors.New(resp.Status)
		body.CloseWithError(err)
		return nil, err
	}

	conn := &http2Conn{
		r:          resp.Body,
		w:          body.Writer(),
		remoteAddr: raddr,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
	}
	return conn, nil
}
