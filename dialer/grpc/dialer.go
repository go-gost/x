package grpc

import (
	"context"
	"net"
	"sync"

	"github.com/go-gost/core/dialer"
	md "github.com/go-gost/core/metadata"
	pb "github.com/go-gost/x/internal/util/grpc/proto"
	"github.com/go-gost/x/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func init() {
	registry.DialerRegistry().Register("grpc", NewDialer)
}

type grpcDialer struct {
	clients     map[string]pb.GostTunelClientX
	clientMutex sync.Mutex
	md          metadata
	options     dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &grpcDialer{
		clients: make(map[string]pb.GostTunelClientX),
		options: options,
	}
}

func (d *grpcDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

// Multiplex implements dialer.Multiplexer interface.
func (d *grpcDialer) Multiplex() bool {
	return true
}

func (d *grpcDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
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
		// d.options.Logger.Infof("grpc dialer, addr %s, host %s/%s", addr, d.md.host, options.Host)

		grpcOpts := []grpc.DialOption{
			// grpc.WithBlock(),
			grpc.WithContextDialer(func(c context.Context, s string) (net.Conn, error) {
				return options.Dialer.Dial(c, "tcp", s)
			}),
			grpc.WithAuthority(host),
			grpc.WithConnectParams(grpc.ConnectParams{
				Backoff:           backoff.DefaultConfig,
				MinConnectTimeout: d.md.minConnectTimeout,
			}),
		}
		if !d.md.insecure {
			grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewTLS(d.options.TLSConfig)))
		} else {
			grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		if d.md.keepalive {
			grpcOpts = append(grpcOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                d.md.keepaliveTime,
				Timeout:             d.md.keepaliveTimeout,
				PermitWithoutStream: d.md.keepalivePermitWithoutStream,
			}))
		}

		cc, err := grpc.NewClient(addr, grpcOpts...)
		if err != nil {
			d.options.Logger.Error(err)
			return nil, err
		}
		client = pb.NewGostTunelClientX(cc)
		d.clients[addr] = client
	}

	ctx2, cancel := context.WithCancel(context.Background())
	cli, err := client.TunnelX(ctx2, d.md.path)
	if err != nil {
		cancel()
		return nil, err
	}

	return &conn{
		c:          cli,
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
		cancelFunc: cancel,
	}, nil
}
