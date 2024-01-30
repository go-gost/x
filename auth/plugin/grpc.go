package auth

import (
	"context"
	"io"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/auth/proto"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.AuthenticatorClient
	log    logger.Logger
}

// NewGRPCPlugin creates an Authenticator plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) auth.Authenticator {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "auther",
		"auther": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}

	if conn != nil {
		p.client = proto.NewAuthenticatorClient(conn)
	}
	return p
}

// Authenticate checks the validity of the provided user-password pair.
func (p *grpcPlugin) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if p.client == nil {
		return "", false
	}

	r, err := p.client.Authenticate(ctx,
		&proto.AuthenticateRequest{
			Username: user,
			Password: password,
			Client:   string(ctxvalue.ClientAddrFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return "", false
	}
	return r.Id, r.Ok
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
