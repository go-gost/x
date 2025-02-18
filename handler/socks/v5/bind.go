package v5

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
)

func (h *socks5Handler) handleBind(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", address, network),
		"cmd": "bind",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), address)

	if !h.md.enableBind {
		reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		log.Trace(reply)
		log.Error("socks5: BIND is disabled")
		return reply.Write(conn)
	}

	{
		clientID := ctxvalue.ClientIDFromContext(ctx)
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			conn,
			string(clientID),
			limiter.ServiceOption(h.options.Service),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.NetworkOption(network),
			limiter.AddrOption(address),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	// BIND does not support chain.
	return h.bindLocal(ctx, conn, network, address, log)
}

func (h *socks5Handler) bindLocal(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}
	ln, err := lc.Listen(ctx, network, address) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Error(err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		if err := reply.Write(conn); err != nil {
			log.Error(err)
		}
		log.Debug(reply)
		return err
	}

	socksAddr := gosocks5.Addr{}
	if err := socksAddr.ParseFrom(ln.Addr().String()); err != nil {
		log.Warn(err)
	}

	// Issue: may not reachable when host has multi-interface
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	socksAddr.Type = 0
	reply := gosocks5.NewReply(gosocks5.Succeeded, &socksAddr)
	log.Trace(reply)
	if err := reply.Write(conn); err != nil {
		log.Error(err)
		ln.Close()
		return err
	}

	log = log.WithFields(map[string]any{
		"bind": fmt.Sprintf("%s/%s", ln.Addr(), ln.Addr().Network()),
	})

	log.Debugf("bind on %s OK", ln.Addr())

	h.serveBind(ctx, conn, ln, log)
	return nil
}

func (h *socks5Handler) serveBind(ctx context.Context, conn net.Conn, ln net.Listener, log logger.Logger) {
	var rc net.Conn
	accept := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer ln.Close()

			c, err := ln.Accept()
			if err != nil {
				errc <- err
			}
			rc = c
		}()

		return errc
	}

	pc1, pc2 := net.Pipe()
	pipe := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer pc1.Close()

			errc <- xnet.Transport(conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	select {
	case err := <-accept():
		if err != nil {
			log.Error(err)

			reply := gosocks5.NewReply(gosocks5.Failure, nil)
			log.Trace(reply)
			if err := reply.Write(pc2); err != nil {
				log.Error(err)
			}

			return
		}
		defer rc.Close()

		log.Debugf("peer %s accepted", rc.RemoteAddr())

		log = log.WithFields(map[string]any{
			"local":  rc.LocalAddr().String(),
			"remote": rc.RemoteAddr().String(),
		})

		raddr := gosocks5.Addr{}
		raddr.ParseFrom(rc.RemoteAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, &raddr)
		log.Trace(reply)
		if err := reply.Write(pc2); err != nil {
			log.Error(err)
		}

		start := time.Now()
		log.Debugf("%s <-> %s", rc.LocalAddr(), rc.RemoteAddr())
		xnet.Transport(pc2, rc)
		log.WithFields(map[string]any{"duration": time.Since(start)}).
			Debugf("%s >-< %s", rc.LocalAddr(), rc.RemoteAddr())

	case err := <-pipe():
		if err != nil {
			log.Error(err)
		}
		ln.Close()
		return
	}
}
