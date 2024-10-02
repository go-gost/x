package auto

import (
	"bufio"
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks4"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
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
	b, err := br.Peek(1)
	if err != nil {
		log.Error(err)
		conn.Close()
		return err
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)
	switch b[0] {
	case gosocks4.Ver4: // socks4
		if h.socks4Handler != nil {
			return h.socks4Handler.Handle(ctx, conn)
		}
	case gosocks5.Ver5: // socks5
		if h.socks5Handler != nil {
			return h.socks5Handler.Handle(ctx, conn)
		}
	default: // http
		if h.httpHandler != nil {
			return h.httpHandler.Handle(ctx, conn)
		}
	}
	return nil
}
