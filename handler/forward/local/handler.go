package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("tcp", NewHandler)
	registry.HandlerRegistry().Register("udp", NewHandler)
	registry.HandlerRegistry().Register("forward", NewHandler)
}

type forwardHandler struct {
	hop      hop.Hop
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &forwardHandler{
		options: options,
	}
}

func (h *forwardHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

// Forward implements handler.Forwarder.
func (h *forwardHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *forwardHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.Duration = time.Since(start)
		ro.Record(ctx, h.recorder.Recorder)

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	network := "tcp"
	if _, ok := conn.(net.PacketConn); ok {
		network = "udp"
	}
	ro.Network = network

	var rw io.ReadWriter = conn
	var proto string
	if network == "tcp" && h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ = sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		rw = xio.NewReadWriter(br, conn)
		switch proto {
		case sniffing.ProtoHTTP:
			ro2 := &xrecorder.HandlerRecorderObject{}
			*ro2 = *ro
			ro.Time = time.Time{}
			return h.handleHTTP(ctx, rw, ro2, log)
		case sniffing.ProtoTLS:
			return h.handleTLS(ctx, xnet.NewReadWriteConn(rw, rw, conn), ro, log)
		}
	}

	var target *chain.Node
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.ProtocolSelectOption(proto),
		)
	}
	if target == nil {
		err := errors.New("node not available")
		log.Error(err)
		return err
	}

	addr := target.Addr
	if opts := target.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":0"
			}
		}
	}

	ro.Network = network
	ro.Host = addr

	log = log.WithFields(map[string]any{
		"node": target.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, network),
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), network, addr)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func (h *forwardHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
