package auto

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks4"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("auto", NewHandler)
}

type autoHandler struct {
	httpHandler   handler.Handler
	socks4Handler handler.Handler
	socks5Handler handler.Handler
	options       handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	h := &autoHandler{
		options: options,
	}

	if f := registry.HandlerRegistry().Get("http"); f != nil {
		v := append(opts,
			handler.LoggerOption(options.Logger.WithFields(map[string]any{"handler": "http"})))
		h.httpHandler = f(v...)
	}
	if f := registry.HandlerRegistry().Get("socks4"); f != nil {
		v := append(opts,
			handler.LoggerOption(options.Logger.WithFields(map[string]any{"handler": "socks4"})))
		h.socks4Handler = f(v...)
	}
	if f := registry.HandlerRegistry().Get("socks5"); f != nil {
		v := append(opts,
			handler.LoggerOption(options.Logger.WithFields(map[string]any{"handler": "socks5"})))
		h.socks5Handler = f(v...)
	}

	return h
}

func (h *autoHandler) Init(md md.Metadata) error {
	if h.httpHandler != nil {
		if err := h.httpHandler.Init(md); err != nil {
			return err
		}
	}
	if h.socks4Handler != nil {
		if err := h.socks4Handler.Init(md); err != nil {
			return err
		}
	}
	if h.socks5Handler != nil {
		if err := h.socks5Handler.Init(md); err != nil {
			return err
		}
	}

	return nil
}

func (h *autoHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	if log.IsLevelEnabled(logger.DebugLevel) {
		start := time.Now()
		log.Debugf("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
		defer func() {
			log.WithFields(map[string]any{
				"duration": time.Since(start),
			}).Debugf("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
		}()
	}

	br := bufio.NewReader(conn)

	// Peek 1 byte first to detect small protocols (SOCKS4/SOCKS5)
	// that send fewer bytes than the 5-byte TLS record header that
	// Sniff() needs.  If we called Sniff() first, its Peek(5) would
	// block indefinitely on a SOCKS5 greeting (3 bytes: VER, NMETHODS,
	// METHODS), deadlocking with the client that is itself waiting for
	// the server's method-selection reply.
	b, err := br.Peek(1)
	if err != nil {
		log.Error(err)
		conn.Close()
		return err
	}

	switch b[0] {
	case gosocks4.Ver4:
		conn = xnet.NewReadWriteConn(br, conn, conn)
		if h.socks4Handler != nil {
			return h.socks4Handler.Handle(ctx, conn)
		}
		return nil
	case gosocks5.Ver5:
		conn = xnet.NewReadWriteConn(br, conn, conn)
		if h.socks5Handler != nil {
			return h.socks5Handler.Handle(ctx, conn)
		}
		return nil
	}

	// Not SOCKS — sniff for TLS, HTTP, or SSH.
	proto, _ := sniffing.Sniff(ctx, br)

	conn = xnet.NewReadWriteConn(br, conn, conn)

	if proto == sniffing.ProtoTLS {
		return h.handleTLS(ctx, conn, log)
	}

	// Default to HTTP.
	if h.httpHandler != nil {
		return h.httpHandler.Handle(ctx, conn)
	}
	return nil
}

// handleTLS forwards a TLS connection that arrived at the auto handler.
// It parses the ClientHello for SNI, dials upstream through the router,
// forwards the ClientHello, records ServerHello metadata, and pipes data
// bidirectionally.
func (h *autoHandler) handleTLS(ctx context.Context, conn net.Conn, log logger.Logger) error {
	ro := &xrecorder.HandlerRecorderObject{
		Network:    "tcp",
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		SID:        ctxvalue.SidFromContext(ctx).String(),
		Time:       time.Now(),
	}
	sniffer := &sniffing.Sniffer{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var buf bytes.Buffer
		cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", address)
		if err != nil {
			return nil, err
		}
		ro.Route = buf.String()
		return cc, nil
	}
	return sniffer.HandleTLS(ctx, "tcp", conn,
		sniffing.WithDial(dial),
		sniffing.WithBypass(h.options.Bypass),
		sniffing.WithRecorderObject(ro),
		sniffing.WithLog(log),
	)
}
