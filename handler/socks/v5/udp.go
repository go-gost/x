package v5

import (
	"context"
	"errors"
	"fmt"
	"io"
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

func (h *socks5Handler) handleUDP(ctx context.Context, conn net.Conn, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"cmd": "udp",
	})

	if !h.md.enableUDP {
		reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		log.Trace(reply)
		log.Error("socks5: UDP relay is disabled")
		return reply.Write(conn)
	}

	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}
	laddr := &net.UDPAddr{IP: conn.LocalAddr().(*net.TCPAddr).IP, Port: 0} // use out-going interface's IP
	cc, err := lc.ListenPacket(ctx, "udp", laddr.String())
	if err != nil {
		log.Error(err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		log.Trace(reply)
		reply.Write(conn)
		return err
	}
	defer cc.Close()

	saddr := gosocks5.Addr{}
	saddr.ParseFrom(cc.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, &saddr)
	log.Trace(reply)
	if err := reply.Write(conn); err != nil {
		log.Error(err)
		return err
	}

	log = log.WithFields(map[string]any{
		"bind": fmt.Sprintf("%s/%s", cc.LocalAddr(), cc.LocalAddr().Network()),
	})
	log.Debugf("bind on %s OK", cc.LocalAddr())

	// obtain a udp connection
	c, err := h.router.Dial(ctx, "udp", "") // UDP association
	if err != nil {
		log.Error(err)
		return err
	}
	defer c.Close()

	pc, ok := c.(net.PacketConn)
	if !ok {
		err := errors.New("socks5: wrong connection type")
		log.Error(err)
		return err
	}

	clientID := ctxvalue.ClientIDFromContext(ctx)
	if h.options.Observer != nil {
		pstats := h.stats.Stats(string(clientID))
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		cc = stats_wrapper.WrapPacketConn(cc, pstats)
	}

	r := udp.NewRelay(socks.UDPConn(cc, h.md.udpBufferSize), pc).
		WithBypass(h.options.Bypass).
		WithLogger(log)
	r.SetBufferSize(h.md.udpBufferSize)

	go r.Run(ctx)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.LocalAddr())
	io.Copy(io.Discard, conn)
	log.WithFields(map[string]any{"duration": time.Since(t)}).
		Debugf("%s >-< %s", conn.RemoteAddr(), cc.LocalAddr())

	return nil
}
