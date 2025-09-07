package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	xctx "github.com/go-gost/x/ctx"
	pb "github.com/go-gost/x/internal/util/grpc/proto"
	mdata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type server struct {
	cqueue    chan net.Conn
	localAddr net.Addr
	pb.UnimplementedGostTunelServer
	logger logger.Logger
}

func (s *server) Tunnel(srv pb.GostTunel_TunnelServer) error {
	c := &conn{
		s:          srv,
		localAddr:  s.localAddr,
		remoteAddr: &net.TCPAddr{},
		closed:     make(chan struct{}),
	}
	if p, ok := peer.FromContext(srv.Context()); ok {
		c.remoteAddr = p.Addr
	}

	ctx := srv.Context()
	if md, ok := mdata.FromIncomingContext(srv.Context()); ok {
		if cip := getClientIP(md); cip != nil {
			ctx = xctx.ContextWithSrcAddr(ctx, &net.TCPAddr{IP: cip})
		}
	}

	c.ctx = ctx

	select {
	case s.cqueue <- c:
	default:
		c.Close()
		s.logger.Warnf("connection queue is full, client discarded")
	}

	<-c.closed

	return nil
}

func getClientIP(md mdata.MD) net.IP {
	if md == nil {
		return nil
	}
	var cip string
	// cloudflare CDN
	if v := md.Get("CF-Connecting-IP"); len(v) > 0 {
		cip = v[0]
	}
	if cip == "" {
		if v := md.Get("X-Forwarded-For"); len(v) > 0 {
			ss := strings.Split(v[0], ",")
			if len(ss) > 0 && ss[0] != "" {
				cip = ss[0]
			}

		}
	}
	if cip == "" {
		if v := md.Get("X-Real-Ip"); len(v) > 0 {
			cip = v[0]
		}
	}

	return net.ParseIP(cip)
}

type conn struct {
	s          pb.GostTunel_TunnelServer
	rb         []byte
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     chan struct{}
	ctx        context.Context
	mu         sync.Mutex
}

func (c *conn) Read(b []byte) (n int, err error) {
	select {
	case <-c.s.Context().Done():
		err = c.s.Context().Err()
		return
	case <-c.closed:
		err = io.ErrClosedPipe
		return
	default:
	}

	if len(c.rb) == 0 {
		chunk, err := c.s.Recv()
		if err != nil {
			return 0, err
		}
		c.rb = chunk.Data
	}

	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
}

func (c *conn) Write(b []byte) (n int, err error) {
	select {
	case <-c.s.Context().Done():
		err = c.s.Context().Err()
		return
	case <-c.closed:
		err = io.ErrClosedPipe
		return
	default:
	}

	if err = c.s.Send(&pb.Chunk{
		Data: b,
	}); err != nil {
		return
	}
	n = len(b)
	return
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
	default:
		close(c.closed)
	}

	return nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "grpc", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "grpc", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "grpc", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *conn) Context() context.Context {
	return c.ctx
}
