package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/recorder"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/forward"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
)

func init() {
	registry.HandlerRegistry().Register("rtcp", NewHandler)
	registry.HandlerRegistry().Register("rudp", NewHandler)
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

func (h *forwardHandler) Init(md mdata.Metadata) (err error) {
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
		if !ro.Time.IsZero() {
			if err != nil {
				ro.Err = err.Error()
			}
			ro.Duration = time.Since(start)
			ro.Record(ctx, h.recorder.Recorder)
		}

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

	localAddr := convertAddr(conn.LocalAddr())

	var rw io.ReadWriter = conn
	var host string
	var protocol string
	if network == "tcp" && h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}
		rw, host, protocol, _ = forward.Sniffing(ctx, conn)
		log.Debugf("sniffing: host=%s, protocol=%s", host, protocol)
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}
	}
	if protocol == forward.ProtoHTTP {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro.Time = time.Time{}

		h.handleHTTP(ctx, xio.NewReadWriteCloser(rw, rw, conn), conn.RemoteAddr(), localAddr, ro2, log)
		return nil
	}

	if md, ok := conn.(mdata.Metadatable); ok {
		if v := mdutil.GetString(md.Metadata(), "host"); v != "" {
			host = v
		}
	}
	var target *chain.Node
	if host != "" {
		target = &chain.Node{
			Addr: host,
		}
	}
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(protocol),
		)
	}
	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	if opts := target.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
		}
	}

	ro.Network = network
	ro.Host = target.Addr

	log = log.WithFields(map[string]any{
		"host": host,
		"node": target.Name,
		"dst":  fmt.Sprintf("%s/%s", target.Addr, network),
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

	cc, err := h.options.Router.Dial(ctx, network, target.Addr)
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	defer cc.Close()
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	cc = proxyproto.WrapClientConn(h.md.proxyProtocol, conn.RemoteAddr(), localAddr, cc)

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func (h *forwardHandler) handleHTTP(ctx context.Context, rw io.ReadWriteCloser, remoteAddr net.Addr, localAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	br := bufio.NewReader(rw)

	for {
		var cc net.Conn
		resp := &http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			StatusCode: http.StatusServiceUnavailable,
		}

		err = func() error {
			req, err := http.ReadRequest(br)
			if err != nil {
				// log.Errorf("read http request: %v", err)
				return err
			}

			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(req, false)
				log.Trace(string(dump))
			}

			start := time.Now()
			ro.Time = start
			ro.HTTP = &xrecorder.HTTPRecorderObject{
				Host:   req.Host,
				Proto:  req.Proto,
				Scheme: req.URL.Scheme,
				Method: req.Method,
				URI:    req.RequestURI,
				Request: xrecorder.HTTPRequestRecorderObject{
					ContentLength: req.ContentLength,
					Header:        req.Header.Clone(),
				},
			}
			if clientIP := xhttp.GetClientIP(req); clientIP != nil {
				ro.ClientIP = clientIP.String()
			}

			defer func() {
				if err != nil {
					ro.HTTP.StatusCode = resp.StatusCode
					ro.HTTP.Response.Header = resp.Header

					ro.Duration = time.Since(start)
					ro.Err = err.Error()
					ro.Record(ctx, h.recorder.Recorder)
				}
			}()

			host := req.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
			}
			if bp := h.options.Bypass; bp != nil && bp.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
				log.Debugf("bypass: %s %s", host, req.RequestURI)
				resp.StatusCode = http.StatusForbidden
				resp.Write(rw)
				return xbypass.ErrBypass
			}

			if addr := getRealClientAddr(req, remoteAddr); addr != remoteAddr {
				log = log.WithFields(map[string]any{
					"src": addr.String(),
				})
				remoteAddr = addr
				ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(remoteAddr.String()))
			}

			target := &chain.Node{
				Addr: req.Host,
			}
			if h.hop != nil {
				target = h.hop.Select(ctx,
					hop.HostSelectOption(req.Host),
					hop.ProtocolSelectOption(forward.ProtoHTTP),
					hop.PathSelectOption(req.URL.Path),
				)
			}
			if target == nil {
				log.Warnf("node for %s not found", req.Host)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(rw)
			}

			ro.Host = target.Addr

			log = log.WithFields(map[string]any{
				"host": req.Host,
				"node": target.Name,
				"dst":  target.Addr,
			})
			log.Debugf("find node for host %s -> %s(%s)", req.Host, target.Name, target.Addr)

			var bodyRewrites []chain.HTTPBodyRewriteSettings
			if httpSettings := target.Options().HTTP; httpSettings != nil {
				if auther := httpSettings.Auther; auther != nil {
					username, password, _ := req.BasicAuth()
					id, ok := auther.Authenticate(ctx, username, password)
					if !ok {
						resp.StatusCode = http.StatusUnauthorized
						resp.Header.Set("WWW-Authenticate", "Basic")
						log.Warnf("node %s(%s) 401 unauthorized", target.Name, target.Addr)
						return resp.Write(rw)
					}
					ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(id))
				}
				if httpSettings.Host != "" {
					req.Host = httpSettings.Host
				}
				for k, v := range httpSettings.Header {
					req.Header.Set(k, v)
				}

				for _, re := range httpSettings.RewriteURL {
					if re.Pattern.MatchString(req.URL.Path) {
						if s := re.Pattern.ReplaceAllString(req.URL.Path, re.Replacement); s != "" {
							req.URL.Path = s
							break
						}
					}
				}

				bodyRewrites = httpSettings.RewriteBody
			}

			cc, err = h.options.Router.Dial(ctx, "tcp", target.Addr)
			if err != nil {
				// TODO: the router itself may be failed due to the failed node in the router,
				// the dead marker may be a wrong operation.
				if marker := target.Marker(); marker != nil {
					marker.Mark()
				}
				log.Warnf("connect to node %s(%s) failed: %v", target.Name, target.Addr, err)
				return resp.Write(rw)
			}
			if marker := target.Marker(); marker != nil {
				marker.Reset()
			}

			log.Debugf("new connection to node %s(%s)", target.Name, target.Addr)

			if tlsSettings := target.Options().TLS; tlsSettings != nil {
				cfg := &tls.Config{
					ServerName:         tlsSettings.ServerName,
					InsecureSkipVerify: !tlsSettings.Secure,
				}
				tls_util.SetTLSOptions(cfg, &config.TLSOptions{
					MinVersion:   tlsSettings.Options.MinVersion,
					MaxVersion:   tlsSettings.Options.MaxVersion,
					CipherSuites: tlsSettings.Options.CipherSuites,
				})
				cc = tls.Client(cc, cfg)
			}

			cc = proxyproto.WrapClientConn(h.md.proxyProtocol, remoteAddr, localAddr, cc)

			var reqBody *xhttp.Body
			if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
				if req.Body != nil {
					maxSize := opts.MaxBodySize
					if maxSize <= 0 {
						maxSize = defaultBodySize
					}
					reqBody = xhttp.NewBody(req.Body, maxSize)
					req.Body = reqBody
				}
			}

			if err = req.Write(cc); err != nil {
				cc.Close()
				log.Warnf("send request to node %s(%s): %v", target.Name, target.Addr, err)
				resp.Write(rw)
				return err
			}

			if reqBody != nil {
				ro.HTTP.Request.Body = reqBody.Content()
				ro.HTTP.Request.ContentLength = reqBody.Length()
			}

			if req.Header.Get("Upgrade") == "websocket" {
				err := xnet.Transport(cc, xio.NewReadWriter(br, rw))
				if err == nil {
					err = io.EOF
				}
				return err
			}

			go func() {
				defer cc.Close()

				var err error
				var res *http.Response
				var respBody *xhttp.Body

				defer func() {
					ro.Duration = time.Since(start)
					if err != nil {
						ro.Err = err.Error()
					}
					if res != nil {
						ro.HTTP.StatusCode = res.StatusCode
						ro.HTTP.Response.Header = res.Header
						ro.HTTP.Response.ContentLength = res.ContentLength
						if respBody != nil {
							ro.HTTP.Response.Body = respBody.Content()
							ro.HTTP.Response.ContentLength = respBody.Length()
						}
					}
					ro.Record(ctx, h.recorder.Recorder)
				}()

				res, err = http.ReadResponse(bufio.NewReader(cc), req)
				if err != nil {
					log.Warnf("read response from node %s(%s): %v", target.Name, target.Addr, err)
					resp.Write(rw)
					return
				}
				defer res.Body.Close()

				if log.IsLevelEnabled(logger.TraceLevel) {
					dump, _ := httputil.DumpResponse(res, false)
					log.Trace(string(dump))
				}

				if res.Close {
					defer rw.Close()
				}

				if err = h.rewriteBody(res, bodyRewrites...); err != nil {
					rw.Close()
					log.Errorf("rewrite body: %v", err)
					return
				}

				if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
					maxSize := opts.MaxBodySize
					if maxSize <= 0 {
						maxSize = defaultBodySize
					}
					respBody = xhttp.NewBody(res.Body, maxSize)
					res.Body = respBody
				}

				if err = res.Write(rw); err != nil {
					rw.Close()
					log.Errorf("write response from node %s(%s): %v", target.Name, target.Addr, err)
				}
			}()

			return nil
		}()

		if err != nil {
			if cc != nil {
				cc.Close()
			}
			break
		}
	}

	return
}

func (h *forwardHandler) rewriteBody(resp *http.Response, rewrites ...chain.HTTPBodyRewriteSettings) error {
	if resp == nil || len(rewrites) == 0 || resp.ContentLength <= 0 {
		return nil
	}

	body, err := drainBody(resp.Body)
	if err != nil || body == nil {
		return err
	}

	contentType, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	for _, rewrite := range rewrites {
		rewriteType := rewrite.Type
		if rewriteType == "" {
			rewriteType = "text/html"
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, contentType) {
			continue
		}

		body = rewrite.Pattern.ReplaceAll(body, rewrite.Replacement)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	return nil
}

func drainBody(b io.ReadCloser) (body []byte, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, err
	}
	if err = b.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

func convertAddr(addr net.Addr) net.Addr {
	host, sp, _ := net.SplitHostPort(addr.String())
	ip := net.ParseIP(host)
	port, _ := strconv.Atoi(sp)

	if ip == nil || ip.Equal(net.IPv6zero) {
		ip = net.IPv4zero
	}

	switch addr.Network() {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}

	default:
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	}
}

func getRealClientAddr(req *http.Request, raddr net.Addr) net.Addr {
	if req == nil {
		return nil
	}
	// cloudflare CDN
	sip := req.Header.Get("CF-Connecting-IP")
	if sip == "" {
		ss := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
		if len(ss) > 0 && ss[0] != "" {
			sip = ss[0]
		}
	}
	if sip == "" {
		sip = req.Header.Get("X-Real-Ip")
	}

	ip := net.ParseIP(sip)
	if ip == nil {
		return raddr
	}

	_, sp, _ := net.SplitHostPort(raddr.String())

	port, _ := strconv.Atoi(sp)

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}
