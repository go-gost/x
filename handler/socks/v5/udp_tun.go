package v5

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/socks"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
)

func (h *socks5Handler) handleUDPTun(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"cmd": "udp-tun",
	})

	bindAddr, _ := net.ResolveUDPAddr(network, address)
	if bindAddr == nil {
		bindAddr = &net.UDPAddr{}
	}

	var pc net.PacketConn
	// relay mode
	if bindAddr.Port == 0 {
		if !h.md.enableUDP {
			reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
			log.Trace(reply)
			log.Error("socks5: UDP relay is disabled")
			return reply.Write(conn)
		}

		// obtain a udp connection
		c, err := h.router.Dial(ctx, "udp", "") // UDP association
		if err != nil {
			log.Error(err)
			return err
		}
		defer c.Close()

		var ok bool
		pc, ok = c.(net.PacketConn)
		if !ok {
			err := errors.New("socks5: wrong connection type")
			log.Error(err)
			return err
		}

	} else { // BIND mode
		if !h.md.enableBind {
			reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
			log.Trace(reply)
			log.Error("socks5: BIND is disabled")
			return reply.Write(conn)
		}

		lc := xnet.ListenConfig{
			Netns: h.options.Netns,
		}
		var err error
		pc, err = lc.ListenPacket(ctx, "udp", bindAddr.String())
		if err != nil {
			log.Error(err)
			reply := gosocks5.NewReply(gosocks5.Failure, nil)
			log.Trace(reply)
			reply.Write(conn)
			return err
		}
	}
	defer pc.Close()

	saddr := gosocks5.Addr{}
	saddr.ParseFrom(pc.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, &saddr)
	log.Trace(reply)
	if err := reply.Write(conn); err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("bind on %s OK", pc.LocalAddr())

	clientID := ctxvalue.ClientIDFromContext(ctx)
	if h.options.Observer != nil {
		pstats := h.stats.Stats(string(clientID))
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		conn = stats_wrapper.WrapConn(conn, pstats)
	}

	r := udp.NewRelay(socks.UDPTunServerConn(conn), pc).
		WithBypass(h.options.Bypass).
		WithLogger(log)
	r.SetBufferSize(h.md.udpBufferSize)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), pc.LocalAddr())
	r.Run(ctx)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), pc.LocalAddr())

	return nil
}
