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
	GRPC string = "grpc"
	HTTP string = "http"
)

type Options struct {
	Token     string
	TLSConfig *tls.Config
	Header    http.Header
	Timeout   time.Duration
}

type Option func(opts *Options)

func TokenOption(token string) Option {
	return func(opts *Options) {
		opts.Token = token
	}
}

func TLSConfigOption(cfg *tls.Config) Option {
	return func(opts *Options) {
		opts.TLSConfig = cfg
	}
}

func HeaderOption(header http.Header) Option {
	return func(opts *Options) {
		opts.Header = header
	}
}

func TimeoutOption(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

func NewGRPCConn(addr string, opts *Options) (*grpc.ClientConn, error) {
	grpcOpts := []grpc.DialOption{
		// grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.DefaultConfig,
		}),
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

func NewHTTPClient(opts *Options) *http.Client {
	return &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: opts.TLSConfig,
		},
	}
}
