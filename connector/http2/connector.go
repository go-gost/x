package http2

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("http2", NewConnector)
}

type http2Connector struct {
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &http2Connector{
		options: options,
	}
}

func (c *http2Connector) Init(md md.Metadata) (err error) {
	return c.parseMetadata(md)
}

func (c *http2Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"local":   conn.LocalAddr().String(),
		"remote":  conn.RemoteAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(xctx.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	var client *http.Client
	if cc, ok := conn.(xctx.Context); ok {
		if md := ictx.MetadataFromContext(cc.Context()); md != nil {
			client, _ = md.Get("client").(*http.Client)
		}
	}
	if client == nil {
		err := errors.New("http2: wrong connection type")
		log.Error(err)
		return nil, err
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Scheme: "https", Host: conn.RemoteAddr().String()},
		Host:       address,
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     c.md.header,
		Body:       pr,
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	if user := c.options.Auth; user != nil {
		u := user.Username()
		p, _ := user.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	connectCtx := ctx
	if c.md.connectTimeout > 0 {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, c.md.connectTimeout)
		defer cancel()
	}

	// Honor cancellation until CONNECT response headers arrive, while allowing
	// an established tunnel to outlive the caller's connection setup context.
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopCancel := context.AfterFunc(connectCtx, cancel)
	resp, err := client.Do(req.WithContext(requestCtx))
	stopCancel()
	// AfterFunc may already be running. In that case the context is done and
	// this stream must not be returned as a successful connection.
	if connectCtx.Err() != nil {
		err = connectCtx.Err()
	}
	if err != nil {
		cancel()
		pr.CloseWithError(err)
		pw.CloseWithError(err)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		log.Error(err)
		conn.Close()
		return nil, err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s", resp.Status)
		cancel()
		pr.CloseWithError(err)
		pw.CloseWithError(err)
		resp.Body.Close()
		log.Error(err)
		return nil, err
	}

	hc := &http2Conn{
		cancel:    cancel,
		r:         resp.Body,
		w:         pw,
		localAddr: conn.RemoteAddr(),
	}

	hc.remoteAddr, _ = net.ResolveTCPAddr(network, address)

	return hc, nil
}
