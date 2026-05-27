// Package plugin provides shared utilities for building gRPC and HTTP plugin
// clients. Both transport types support authentication tokens, TLS
// configuration, custom headers (HTTP), and connection timeouts.
package plugin

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// GRPC is the transport type identifier for gRPC-based plugins.
	GRPC string = "grpc"
	// HTTP is the transport type identifier for HTTP-based plugins.
	HTTP string = "http"
)

// Options holds the common configuration for gRPC and HTTP plugin clients.
type Options struct {
	Token     string
	TLSConfig *tls.Config
	Header    http.Header
	Timeout   time.Duration
}

// Option configures Options.
type Option func(opts *Options)

// TokenOption sets the authentication token sent with each request.
func TokenOption(token string) Option {
	return func(opts *Options) {
		opts.Token = token
	}
}

// TLSConfigOption sets the TLS configuration for transport security.
func TLSConfigOption(cfg *tls.Config) Option {
	return func(opts *Options) {
		opts.TLSConfig = cfg
	}
}

// HeaderOption sets custom HTTP headers sent with each request (HTTP transport only).
func HeaderOption(header http.Header) Option {
	return func(opts *Options) {
		opts.Header = header
	}
}

// TimeoutOption sets the request timeout (HTTP transport only).
func TimeoutOption(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

// NewGRPCConn creates a gRPC client connection to addr. If opts is nil or
// opts.TLSConfig is nil, the connection uses insecure transport. When
// opts.Token is set, it is attached as per-RPC credentials.
func NewGRPCConn(addr string, opts *Options) (*grpc.ClientConn, error) {
	grpcOpts := []grpc.DialOption{
		// grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.DefaultConfig,
		}),
	}
	if opts == nil {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		return grpc.NewClient(addr, grpcOpts...)
	}
	if opts.TLSConfig != nil {
		grpcOpts = append(grpcOpts,
			grpc.WithAuthority(opts.TLSConfig.ServerName),
			grpc.WithTransportCredentials(credentials.NewTLS(opts.TLSConfig)),
		)
	} else {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if opts.Token != "" {
		grpcOpts = append(grpcOpts, grpc.WithPerRPCCredentials(&rpcCredentials{token: opts.Token}))
	}
	return grpc.NewClient(addr, grpcOpts...)
}

type rpcCredentials struct {
	token string
}

func (c *rpcCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"token": c.token,
	}, nil
}

func (c *rpcCredentials) RequireTransportSecurity() bool {
	return false
}

// NewHTTPClient creates an http.Client from opts. If opts is nil, a default
// client with no timeout is returned. When opts.Token is set, the returned
// client's transport is wrapped so that each outgoing request carries an
// "Authorization: Bearer <token>" header (unless the caller has already set
// its own Authorization header). Use HTTPClientTransport to access the
// underlying *http.Transport and close idle connections when the client is no
// longer needed.
func NewHTTPClient(opts *Options) *http.Client {
	if opts == nil {
		return &http.Client{}
	}
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: opts.TLSConfig,
	}
	if opts.Token != "" {
		transport = &tokenTransport{base: transport, token: opts.Token}
	}
	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}
}

// tokenTransport is an http.RoundTripper that injects a bearer token into the
// "Authorization" header of every outgoing request. It does not overwrite an
// Authorization header that the caller has already set.
type tokenTransport struct {
	base  http.RoundTripper
	token string
}

// RoundTrip injects the bearer token when the request has no Authorization
// header. It clones the request before mutating its headers so that the
// caller's request value is not modified.
func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// CloseIdleConnections delegates to the underlying transport so that
// http.Client.CloseIdleConnections() works through the tokenTransport
// wrapper instead of silently becoming a no-op.
func (t *tokenTransport) CloseIdleConnections() {
	type closeIdler interface {
		CloseIdleConnections()
	}
	if tr, ok := t.base.(closeIdler); ok {
		tr.CloseIdleConnections()
	}
}

// HTTPClientTransport returns the *http.Transport underlying c, or nil if c's
// transport is not an *http.Transport. When the client was created with a
// non-empty Token, the *http.Transport is unwrapped from the tokenTransport
// wrapper. Callers that hold the client for a long time should call
// tr.CloseIdleConnections() when the client is no longer needed.
func HTTPClientTransport(c *http.Client) *http.Transport {
	if c == nil {
		return nil
	}
	rt := c.Transport
	if tt, ok := rt.(*tokenTransport); ok {
		rt = tt.base
	}
	tr, _ := rt.(*http.Transport)
	return tr
}
