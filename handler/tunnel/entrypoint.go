package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	dissector "github.com/go-gost/tls-dissector"
	admission "github.com/go-gost/x/admission/wrapper"
	ctxvalue "github.com/go-gost/x/ctx"
	ctx_internal "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	ws_util "github.com/go-gost/x/internal/util/ws"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/time/rate"
)

const (
	httpHeaderSID           = "Gost-Sid"
	httpHeaderForwardedNode = "Gost-Forwarded-Node"
)

type entrypoint struct {
	node      string
	service   string
	pool      *ConnectorPool
	ingress   ingress.Ingress
	sd        sd.SD
	log       logger.Logger
	recorder  recorder.RecorderObject
	transport http.RoundTripper

	sniffingWebsocket   bool
	websocketSampleRate float64

	readTimeout time.Duration
}

func (ep *entrypoint) Handle(ctx context.Context, conn net.Conn) (err error) {
	defer conn.Close()

	ro := &xrecorder.HandlerRecorderObject{
		Node:       ep.node,
		Service:    ep.service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       time.Now(),
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := ep.log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ro.SID,
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
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	br := bufio.NewReader(conn)
	v, err := br.Peek(1)
	if err != nil {
		return err
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)
	if v[0] == relay.Version1 {
		return ep.handleConnect(ctx, conn, ro, log)
	}
	if v[0] == dissector.Handshake {
		return ep.HandleTLS(ctx, conn, ro, log)
	}
	return ep.handleHTTP(ctx, conn, ro, log)
}

func (ep *entrypoint) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var tunnelID relay.TunnelID
	if ep.ingress != nil {
		if rule := ep.ingress.GetRule(ctx, addr); rule != nil {
			tunnelID = parseTunnelID(rule.Endpoint)
		}
	}

	log := ctxvalue.LoggerFromContext(ctx)
	if log == nil {
		log = ep.log
	}
	log.Debugf("dial: new connection to host %s", addr)

	if tunnelID.IsZero() {
		return nil, fmt.Errorf("%w %s", ErrTunnelRoute, addr)
	}

	ro := ctx_internal.RecorderObjectFromContext(ctx)
	ro.ClientID = tunnelID.String()

	if tunnelID.IsPrivate() {
		return nil, fmt.Errorf("%w: tunnel %s is private for host %s", ErrPrivateTunnel, tunnelID, addr)
	}

	log = log.WithFields(map[string]any{
		"tunnel": tunnelID.String(),
	})

	d := &Dialer{
		node:    ep.node,
		pool:    ep.pool,
		sd:      ep.sd,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	conn, node, cid, err := d.Dial(ctx, "tcp", tunnelID.String())
	if err != nil {
		return
	}
	log.Debugf("dial: connected to host %s, tunnel: %s, connector: %s", addr, tunnelID, cid)

	if node == ep.node {
		ro.Redirect = ""

		clientAddr := ctxvalue.ClientAddrFromContext(ctx)
		var features []relay.Feature
		af := &relay.AddrFeature{}
		af.ParseFrom(string(clientAddr))
		features = append(features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(addr)
		features = append(features, af) // dst address

		if _, err = (&relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: features,
		}).WriteTo(conn); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		ro.Redirect = node
	}

	return conn, nil
}

func (ep *entrypoint) handleHTTP(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

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

	ro.Time = time.Time{}

	if err := ep.httpRoundTrip(ctx, xio.NewReadWriter(br, conn), req, ro, &pStats, log); err != nil {
		log.Error(err)
		return err
	}

	for {
		pStats.Reset()

		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpRequest(req, false)
			log.Trace(string(dump))
		}

		if err := ep.httpRoundTrip(ctx, xio.NewReadWriter(br, conn), req, ro, &pStats, log); err != nil {
			return err
		}
	}
}

func (ep *entrypoint) httpRoundTrip(ctx context.Context, rw io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (err error) {
	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

	if sid := req.Header.Get(httpHeaderSID); sid != "" {
		ro.SID = sid
	} else {
		req.Header.Set(httpHeaderSID, ro.SID)
	}
	req.Header.Set(httpHeaderForwardedNode, ro.Node)

	host := req.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	ro.Host = host
	ro.Time = time.Now()

	log = log.WithFields(map[string]any{
		"host": host,
	})
	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

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

	clientAddr := ro.RemoteAddr
	if ro.ClientIP != "" {
		if _, port, _ := net.SplitHostPort(ro.RemoteAddr); port != "" {
			clientAddr = net.JoinHostPort(ro.ClientIP, port)
		}
	}

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}
	ro.HTTP.StatusCode = res.StatusCode

	var reqBody *xhttp.Body
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = sniffing.DefaultBodySize
			}
			if bodySize > sniffing.MaxBodySize {
				bodySize = sniffing.MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(clientAddr))
	ctx = ctx_internal.ContextWithRecorderObject(ctx, ro)
	ctx = ctxvalue.ContextWithLogger(ctx, log)

	resp, err := ep.transport.RoundTrip(req.WithContext(ctx))

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		if errors.Is(err, ErrTunnelRoute) || errors.Is(err, ErrPrivateTunnel) {
			res.StatusCode = http.StatusBadGateway
			ro.HTTP.StatusCode = http.StatusBadGateway
		}
		res.Write(rw)
		return
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return ep.handleUpgradeResponse(ctx, rw, req, resp, ro, log)
	}

	var respBody *xhttp.Body
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		return fmt.Errorf("write response: %v", err)
	}

	return
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (ep *entrypoint) handleUpgradeResponse(ctx context.Context, rw io.ReadWriter, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return fmt.Errorf("internal error: 101 switching protocols response with non-writable body")
	}
	defer backConn.Close()

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && ep.sniffingWebsocket {
		return ep.sniffingWebsocketFrame(ctx, rw, backConn, ro, log)
	}

	return xnet.Transport(rw, backConn)
}

func (ep *entrypoint) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := ep.websocketSampleRate
	if sampleRate == 0 {
		sampleRate = sniffing.DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := ep.copyWebsocketFrame(cc, rw, buf, "client", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := ep.copyWebsocketFrame(rw, cc, buf, "server", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	return nil
}

func (ep *entrypoint) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
	fr := ws_util.Frame{}
	if _, err = fr.ReadFrom(r); err != nil {
		return err
	}

	ws := &xrecorder.WebsocketRecorderObject{
		From:    from,
		Fin:     fr.Header.Fin,
		Rsv1:    fr.Header.Rsv1,
		Rsv2:    fr.Header.Rsv2,
		Rsv3:    fr.Header.Rsv3,
		OpCode:  int(fr.Header.OpCode),
		Masked:  fr.Header.Masked,
		MaskKey: fr.Header.MaskKey,
		Length:  fr.Header.PayloadLength,
	}
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}

		buf.Reset()
		if _, err := io.Copy(buf, io.LimitReader(fr.Data, int64(bodySize))); err != nil {
			return err
		}
		ws.Payload = buf.Bytes()
	}

	ro.Websocket = ws
	length := uint64(fr.Header.Length()) + uint64(fr.Header.PayloadLength)
	if from == "client" {
		ro.InputBytes = length
		ro.OutputBytes = 0
	} else {
		ro.InputBytes = 0
		ro.OutputBytes = length
	}

	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}

func (ep *entrypoint) HandleTLS(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
		}
		ro.Host = host
	}

	ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(ro.RemoteAddr))
	ctx = ctx_internal.ContextWithRecorderObject(ctx, ro)
	ctx = ctxvalue.ContextWithLogger(ctx, log)

	cc, err := ep.dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(ep.readTimeout))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
	xio.SetReadDeadline(cc, time.Time{})

	if serverHello != nil {
		ro.TLS.CipherSuite = tls_util.CipherSuite(serverHello.CipherSuite).String()
		ro.TLS.CompressionMethod = serverHello.CompressionMethod
		if serverHello.Proto != "" {
			ro.TLS.Proto = serverHello.Proto
		}
		if serverHello.Version > 0 {
			ro.TLS.Version = tls_util.Version(serverHello.Version).String()
		}
	}

	if buf.Len() > 0 {
		ro.TLS.ServerHello = hex.EncodeToString(buf.Bytes())
	}

	if _, err := buf.WriteTo(conn); err != nil {
		return err
	}

	xnet.Transport(conn, cc)
	return err
}

func (ep *entrypoint) handleConnect(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	req := relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		return err
	}

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	var srcAddr, dstAddr string
	network := "tcp"
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				v := net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
				if srcAddr != "" {
					dstAddr = v
				} else {
					srcAddr = v
				}
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = relay.NewTunnelID(feature.ID[:])
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				network = feature.Network.String()
			}
		}
	}

	if tunnelID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrTunnelID
	}

	ro.ClientID = tunnelID.String()

	d := Dialer{
		pool:    ep.pool,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	cc, _, cid, err := d.Dial(ctx, network, tunnelID.String())
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	af := &relay.AddrFeature{}
	af.ParseFrom(srcAddr)
	resp.Features = append(resp.Features, af) // src address

	af = &relay.AddrFeature{}
	af.ParseFrom(dstAddr)
	resp.Features = append(resp.Features, af) // dst address

	resp.WriteTo(cc)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}

type tcpListener struct {
	ln      net.Listener
	options listener.Options
}

func newTCPListener(ln net.Listener, opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tcpListener{
		ln:      ln,
		options: options,
	}
}

func (l *tcpListener) Init(md md.Metadata) (err error) {
	// l.logger.Debugf("pp: %d", l.options.ProxyProtocol)
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Admission, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	l.ln = ln

	return
}

func (l *tcpListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tcpListener) Close() error {
	return l.ln.Close()
}

type entrypointHandler struct {
	ep *entrypoint
}

func (h *entrypointHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *entrypointHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	return h.ep.Handle(ctx, conn)
}
