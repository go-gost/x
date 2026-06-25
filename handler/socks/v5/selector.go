package v5

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/socks"
)

type serverSelector struct {
	service       string
	methods       []uint8
	Authenticator auth.Authenticator
	TLSConfig     *tls.Config
	logger        logger.Logger
	noTLS         bool
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (s *serverSelector) Select(methods ...uint8) (method uint8) {
	s.logger.Debugf("%d %d %v", gosocks5.Ver5, len(methods), methods)

	// Determine which methods the client offered.
	var hasNoAuth, hasUserPass, hasTLS, hasTLSAuth bool
	for _, m := range methods {
		switch m {
		case gosocks5.MethodNoAuth:
			hasNoAuth = true
		case gosocks5.MethodUserPass:
			hasUserPass = true
		case socks.MethodTLS:
			hasTLS = true
		case socks.MethodTLSAuth:
			hasTLSAuth = true
		}
	}

	// When Authenticator is set, authentication is mandatory.
	if s.Authenticator != nil {
		if hasTLSAuth && !s.noTLS && s.TLSConfig != nil {
			return socks.MethodTLSAuth
		}
		if hasUserPass {
			return gosocks5.MethodUserPass
		}
		return gosocks5.MethodNoAcceptable
	}

	// No authenticator — select the best unauthenticated method.
	if hasTLS && !s.noTLS && s.TLSConfig != nil {
		return socks.MethodTLS
	}
	if hasNoAuth {
		return gosocks5.MethodNoAuth
	}

	return gosocks5.MethodNoAcceptable
}

func (s *serverSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	s.logger.Debugf("%d %d", gosocks5.Ver5, method)
	switch method {
	case gosocks5.MethodNoAuth:

	case socks.MethodTLS:
		conn = tls.Server(conn, s.TLSConfig)

	case gosocks5.MethodUserPass, socks.MethodTLSAuth:
		if method == socks.MethodTLSAuth {
			conn = tls.Server(conn, s.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			s.logger.Error(err)
			return "", nil, err
		}
		s.logger.Trace(req)

		var id string
		if s.Authenticator != nil {
			var ok bool
			ctx := xctx.ContextWithSrcAddr(context.Background(), conn.RemoteAddr())
			id, ok = s.Authenticator.Authenticate(ctx, req.Username, req.Password, auth.WithService(s.service))
			if !ok {
				resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
				if err := resp.Write(conn); err != nil {
					s.logger.Error(err)
					return "", nil, err
				}
				s.logger.Info(resp)

				return "", nil, gosocks5.ErrAuthFailure
			}
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		s.logger.Trace(resp)
		if err := resp.Write(conn); err != nil {
			s.logger.Error(err)
			return "", nil, err
		}
		return id, conn, nil

	case gosocks5.MethodNoAcceptable:
		return "", nil, gosocks5.ErrBadMethod
	default:
		return "", nil, gosocks5.ErrBadFormat
	}
	return "", conn, nil
}
