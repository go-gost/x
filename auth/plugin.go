package auth

import (
	"context"
	"io"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/auth/proto"
	"google.golang.org/grpc"
)

type grpcPluginAuthenticator struct {
	conn   grpc.ClientConnInterface
	client proto.AuthenticatorClient
	log    logger.Logger
}

// NewGRPCPluginAuthenticator creates an Authenticator plugin based on gRPC.
func NewGRPCPluginAuthenticator(name string, conn grpc.ClientConnInterface) auth.Authenticator {
	p := &grpcPluginAuthenticator{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": name,
		}),
	}

	if conn != nil {
		p.client = proto.NewAuthenticatorClient(conn)
	}
	return p
}

// Authenticate checks the validity of the provided user-password pair.
func (p *grpcPluginAuthenticator) Authenticate(ctx context.Context, user, password string) (bool, string) {
	if p.client == nil {
		return false, ""
	}

	r, err := p.client.Authenticate(ctx,
		&proto.AuthenticateRequest{
			Username: user,
			Password: password,
		})
	if err != nil {
		p.log.Error(err)
		return false, ""
	}
	return r.Ok, r.Id
}

func (p *grpcPluginAuthenticator) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
