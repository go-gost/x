package ssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	sshd_util "github.com/go-gost/x/internal/util/sshd"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	"golang.org/x/crypto/ssh"
)

// Applicable SSH Request types for Port Forwarding - RFC 4254 7.X
const (
	ForwardedTCPReturnRequest = "forwarded-tcpip" // RFC 4254 7.2
)

func init() {
	registry.HandlerRegistry().Register("sshd", NewHandler)
}

type forwardHandler struct {
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
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

	if h.md.certificate != nil && h.md.privateKey != nil {
		h.certPool = tls_util.NewMemoryCertPool()
	}

	return nil
}

func (h *forwardHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		Network:    "tcp",
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

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	switch cc := conn.(type) {
	case *sshd_util.DirectForwardConn:
		return h.handleDirectForward(ctx, cc, ro, log)
	case *sshd_util.RemoteForwardConn:
		return h.handleRemoteForward(ctx, cc, ro, log)
	default:
		err := errors.New("sshd: wrong connection type")
		log.Error(err)
		return err
	}
}

func (h *forwardHandler) handleDirectForward(ctx context.Context, conn *sshd_util.DirectForwardConn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	targetAddr := conn.DstAddr()

	ro.Host = targetAddr
	log = log.WithFields(map[string]any{
		"dst":  fmt.Sprintf("%s/%s", targetAddr, "tcp"),
		"cmd":  "connect",
		"host": targetAddr,
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), targetAddr)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", targetAddr) {
		log.Debugf("bypass %s", targetAddr)
		return xbypass.ErrBypass
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", targetAddr)
	ro.Route = buf.String()
	if err != nil {
		return err
	}
	defer cc.Close()

	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return cc, nil
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return cc, nil
		}
		sniffer := &sniffing.Sniffer{
			Websocket:           h.md.sniffingWebsocket,
			WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
			Recorder:            h.recorder.Recorder,
			RecorderOptions:     h.recorder.Options,
			Certificate:         h.md.certificate,
			PrivateKey:          h.md.privateKey,
			NegotiatedProtocol:  h.md.alpn,
			CertPool:            h.certPool,
			MitmBypass:          h.md.mitmBypass,
			ReadTimeout:         h.md.readTimeout,
		}

		switch proto {
		case sniffing.ProtoHTTP:
			return sniffer.HandleHTTP(ctx, xnet.NewReadWriteConn(br, conn, conn),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		case sniffing.ProtoTLS:
			return sniffer.HandleTLS(ctx, xnet.NewReadWriteConn(br, conn, conn),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		}
	}

	t := time.Now()
	log.Infof("%s <-> %s", cc.LocalAddr(), targetAddr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", cc.LocalAddr(), targetAddr)

	return nil
}

func (h *forwardHandler) handleRemoteForward(ctx context.Context, conn *sshd_util.RemoteForwardConn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	req := conn.Request()

	t := tcpipForward{}
	if err := ssh.Unmarshal(req.Payload, &t); err != nil {
		log.Error(err)
		return err
	}

	network := "tcp"
	addr := net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
	ro.Host = addr

	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", addr, network),
		"cmd": "bind",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	// tie to the client connection
	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Error(err)
		req.Reply(false, nil)
		return err
	}
	defer ln.Close()

	log = log.WithFields(map[string]any{
		"bind": fmt.Sprintf("%s/%s", ln.Addr(), ln.Addr().Network()),
	})
	log.Debugf("bind on %s OK", ln.Addr())

	err = func() error {
		if t.Port == 0 && req.WantReply { // Client sent port 0. let them know which port is actually being used
			_, port, err := getHostPortFromAddr(ln.Addr())
			if err != nil {
				return err
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(port))
			t.Port = uint32(port)
			return req.Reply(true, b[:])
		}
		return req.Reply(true, nil)
	}()
	if err != nil {
		log.Error(err)
		return err
	}

	sshConn := conn.Conn()

	go func() {
		for {
			cc, err := ln.Accept()
			if err != nil { // Unable to accept new connection - listener is likely closed
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				log := log.WithFields(map[string]any{
					"local":  conn.LocalAddr().String(),
					"remote": conn.RemoteAddr().String(),
				})

				p := directForward{}
				var err error

				var portnum int
				p.Host1 = t.Host
				p.Port1 = t.Port
				p.Host2, portnum, err = getHostPortFromAddr(conn.RemoteAddr())
				if err != nil {
					return
				}

				p.Port2 = uint32(portnum)
				ch, reqs, err := sshConn.OpenChannel(ForwardedTCPReturnRequest, ssh.Marshal(p))
				if err != nil {
					log.Error("open forwarded channel: ", err)
					return
				}
				defer ch.Close()
				go ssh.DiscardRequests(reqs)

				t := time.Now()
				log.Debugf("%s <-> %s", conn.LocalAddr(), conn.RemoteAddr())
				xnet.Transport(ch, conn)
				log.WithFields(map[string]any{
					"duration": time.Since(t),
				}).Debugf("%s >-< %s", conn.LocalAddr(), conn.RemoteAddr())
			}(cc)
		}
	}()

	tm := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	<-conn.Done()
	log.WithFields(map[string]any{
		"duration": time.Since(tm),
	}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

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

func getHostPortFromAddr(addr net.Addr) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portString)
	return
}

// directForward is structure for RFC 4254 7.2 - can be used for "forwarded-tcpip" and "direct-tcpip"
type directForward struct {
	Host1 string
	Port1 uint32
	Host2 string
	Port2 uint32
}

func (p directForward) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", p.Host2, p.Port2, p.Host1, p.Port1)
}

// tcpipForward is structure for RFC 4254 7.1 "tcpip-forward" request
type tcpipForward struct {
	Host string
	Port uint32
}
