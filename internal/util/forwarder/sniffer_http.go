package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/sniffing"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// borrowBodyPrefix reads up to n bytes from body for inspection without
// consuming the stream: the prefix is re-prepended via MultiReader so the
// full body still flows downstream. It returns the prefix (shorter than n on
// EOF or underlying read error) and the restored ReadCloser to assign back to
// the caller's body field. The read error is intentionally ignored —
// io.LimitReader yields whatever was read, which is all a matcher or recorder
// needs; centralizing it here keeps the swallow in one audited place.
func borrowBodyPrefix(body io.ReadCloser, n int) (prefix []byte, restored io.ReadCloser) {
	prefix, _ = io.ReadAll(io.LimitReader(body, int64(n)))
	restored = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), body))
	return
}

// HandleHTTP sniffs and proxies an HTTP connection. It reads the initial
// request, performs node selection via the configured hop, and forwards the
// request with HTTP keep-alive support.
func (h *Sniffer) HandleHTTP(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}
	ho.readTimeout = h.effectiveReadTimeout(&ho)

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	log := ho.log
	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	ro := ho.recorderObject
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
		clientAddr := &net.TCPAddr{IP: clientIP}
		ro.ClientAddr = clientAddr.String()
		ctx = xctx.ContextWithSrcAddr(ctx, clientAddr)
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	node, cc, err := h.dial(ctx, conn, req, &ho)
	if err != nil {
		return err
	}
	defer func() { cc.Close() }()

	upstreamHost := normalizeHost(ro.HTTP.Host, "80")

	ho.log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	log = ho.log
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()
	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, node, req, &pStats, &ho)
	if err != nil || shouldClose {
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

		// When DNS override directs multiple domains to the same proxy IP,
		// the browser may reuse a keep-alive connection for a different host.
		// Re-dial to ensure requests reach the correct upstream.
		if reqHost := normalizeHost(req.Host, "80"); reqHost != "" && reqHost != upstreamHost {
			cc.Close()
			newNode, res, resolveErr := resolveHTTPNode(ctx, reqHost, req, &ho)
			if resolveErr != nil {
				ro.HTTP.StatusCode = res.StatusCode
				res.Write(conn)
				return resolveErr
			}
			dial := ho.dial
			if dial == nil {
				dial = (&net.Dialer{}).DialContext
			}
			newCC, dialErr := dial(ctx, "tcp", newNode.Addr)
			if dialErr != nil {
				return dialErr
			}
			newCC = tlsWrapConn(newCC, newNode.Options().TLS)
			upstreamHost = reqHost
			node = newNode
			cc = newCC
			ro.Host = reqHost
			ro.SrcAddr = cc.LocalAddr().String()
			ro.DstAddr = cc.RemoteAddr().String()
			log = log.WithFields(map[string]any{
				"host": reqHost,
				"node": node.Name,
				"dst":  node.Addr,
				"src":  cc.LocalAddr().String(),
			})
			ho.log = log
		}

		if shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, node, req, &pStats, &ho); err != nil || shouldClose {
			return err
		}
	}
}

// resolveHTTPNode selects a node for an HTTP request by applying bypass rules
// and hop selection. It returns the selected node or an error response.
func resolveHTTPNode(ctx context.Context, host string, req *http.Request, ho *HandleOptions) (node *chain.Node, res *http.Response, err error) {
	res = &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	if ho.bypass != nil &&
		ho.bypass.Contains(ctx, "tcp", host,
			bypass.WithService(ho.service),
			bypass.WithPathOption(req.RequestURI)) {
		ho.log.Debugf("bypass: %s %s", host, req.RequestURI)
		res.StatusCode = http.StatusForbidden
		return nil, res, xbypass.ErrBypass
	}

	node = &chain.Node{}
	if ho.hop != nil {
		var clientIP net.IP
		if clientAddr, _ := net.ResolveTCPAddr("tcp", ho.recorderObject.ClientAddr); clientAddr != nil {
			clientIP = clientAddr.IP
		}

		// If any node in the hop opts in to body matching, read a sized prefix
		// of the request body now and restore it so the matcher can inspect it
		// without consuming the stream that is still forwarded below.
		var bodyPrefix []byte
		var maxBodySize int
		if nl, ok := ho.hop.(hop.NodeList); ok {
			for _, n := range nl.Nodes() {
				if n == nil {
					continue
				}
				if s := n.Options().MatcherBodySize; s > maxBodySize {
					maxBodySize = s
				}
			}
		}
		if maxBodySize > 0 && req.Body != nil {
			bodyPrefix, req.Body = borrowBodyPrefix(req.Body, maxBodySize)
			// The forwarded body keeps its original encoding; only the prefix shown
			// to body matchers is decoded so BodyRegexp sees plaintext. Best-effort:
			// a truncated compressed stream yields whatever decoded so far, which is
			// where match patterns (e.g. leading JSON fields) live anyway.
			if enc := req.Header.Get("Content-Encoding"); enc != "" && enc != "identity" && len(bodyPrefix) > 0 {
				if decoded, _ := decompressBody(bodyPrefix, enc); len(decoded) > 0 {
					bodyPrefix = decoded
				}
			}
		}

		node = ho.hop.Select(ctx,
			hop.ClientIPSelectOption(clientIP),
			hop.ProtocolSelectOption(sniffing.ProtoHTTP),
			hop.HostSelectOption(host),
			hop.MethodSelectOption(req.Method),
			hop.PathSelectOption(req.URL.Path),
			hop.QuerySelectOption(req.URL.Query()),
			hop.HeaderSelectOption(req.Header),
			hop.BodySelectOption(bodyPrefix),
		)
	}
	if node == nil {
		ho.log.Warnf("node for %s not found", host)
		res.StatusCode = http.StatusBadGateway
		return nil, res, errors.New("node not available")
	}
	if node.Addr == "" {
		node = &chain.Node{
			Name: node.Name,
			Addr: host,
		}
	}
	return node, nil, nil
}

// dial selects a node, establishes a connection, and sends the request upstream.
func (h *Sniffer) dial(ctx context.Context, conn net.Conn, req *http.Request, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	ro := ho.recorderObject
	host := normalizeHost(req.Host, "80")
	if host != "" {
		ro.Host = host
		ho.log = ho.log.WithFields(map[string]any{
			"host": host,
		})
	}

	node, res, resolveErr := resolveHTTPNode(ctx, host, req, ho)
	if resolveErr != nil {
		ro.HTTP.StatusCode = res.StatusCode
		if werr := res.Write(conn); werr != nil {
			ho.log.Warnf("write error response: %v", werr)
		}
		return nil, nil, resolveErr
	}

	// Prepare an error response for potential connection failures.
	res = &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	ro.Host = node.Addr
	ho.log = ho.log.WithFields(map[string]any{
		"node": node.Name,
		"dst":  node.Addr,
	})
	ho.log.Debugf("find node for host %s -> %s(%s)", host, node.Name, node.Addr)

	cc, err = dial(ctx, "tcp", node.Addr)
	if err != nil {
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		if werr := res.Write(conn); werr != nil {
			ho.log.Warnf("write error response: %v", werr)
		}
		return
	}
	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	cc = tlsWrapConn(cc, node.Options().TLS)
	return
}

// httpRoundTrip forwards a single HTTP request/response pair and records
// traffic metadata. Returns whether the connection should be closed.
func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriteCloser, node *chain.Node, req *http.Request, pStats stats.Stats, ho *HandleOptions) (shouldClose bool, err error) {
	shouldClose = true

	log := ho.log
	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *ho.recorderObject

	ro.Time = time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if rerr := ro.Record(ctx, h.Recorder); rerr != nil {
			log.Errorf("record: %v", rerr)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

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

	// Capture pre-rewrite originals only when this node actually configures a
	// rewrite, so the recorder sees both client-sent and forwarded values.
	// Keep these predicates in sync with chain.HTTPNodeSettings' fields: a new
	// rewrite dimension added there must be added here too, or its originals
	// won't be captured.
	httpSettings := node.Options().HTTP
	hasReqRewrite := httpSettings != nil && (httpSettings.Host != "" ||
		len(httpSettings.RequestHeader) > 0 || len(httpSettings.RewriteURL) > 0 ||
		len(httpSettings.RewriteRequestBody) > 0)
	hasRespRewrite := httpSettings != nil && (len(httpSettings.ResponseHeader) > 0 ||
		len(httpSettings.RewriteResponseBody) > 0)
	bodySize := clampBodySize(h.RecorderOptions)

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var responseHeader map[string]string
	var respBodyRewrites []chain.HTTPBodyRewriteSettings
	var reqBodyRewrites []chain.HTTPBodyRewriteSettings
	if httpSettings != nil {
		if auther := httpSettings.Auther; auther != nil {
			username, password, _ := req.BasicAuth()
			id, ok := auther.Authenticate(ctx, username, password, auth.WithService(ho.service))
			if !ok {
				res.StatusCode = http.StatusUnauthorized
				ro.HTTP.StatusCode = res.StatusCode
				res.Header.Set("WWW-Authenticate", "Basic")
				log.Warnf("node %s(%s) 401 unauthorized", node.Name, node.Addr)
				res.Write(rw)
				err = errors.New("unauthorized")
				return
			}
			ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(id))
		}

		if hasReqRewrite {
			ro.HTTP.OriginalHost = ro.HTTP.Host
			ro.HTTP.OriginalURI = ro.HTTP.URI
			ro.HTTP.OriginalRequest = &xrecorder.HTTPRequestRecorderObject{
				ContentLength: ro.HTTP.Request.ContentLength,
				Header:        ro.HTTP.Request.Header.Clone(),
			}
		}

		if httpSettings.Host != "" {
			req.Host = httpSettings.Host
		}
		for k, v := range httpSettings.RequestHeader {
			if v == "" {
				req.Header.Del(k)
			} else {
				req.Header.Set(k, v)
			}
			ro.HTTP.Request.Header = req.Header.Clone()
		}

		for _, re := range httpSettings.RewriteURL {
			if re.Pattern.MatchString(req.URL.Path) {
				if s := re.Pattern.ReplaceAllString(req.URL.Path, re.Replacement); s != "" {
					// Split replacement at '?' so the query portion
					// goes into RawQuery rather than being percent-encoded
					// as part of Path (%3F for '?').
					if path, query, hasQuery := strings.Cut(s, "?"); hasQuery {
						req.URL.Path = path
						req.URL.RawQuery = query
					} else {
						req.URL.Path = s
					}
					ro.HTTP.URI = req.URL.RequestURI()
					break
				}
			}
		}

		responseHeader = httpSettings.ResponseHeader
		respBodyRewrites = httpSettings.RewriteResponseBody
		reqBodyRewrites = httpSettings.RewriteRequestBody
	}

	// Snapshot the original request body before rewriting, restoring it via
	// MultiReader so the body is read from the wire only once. Only when body
	// recording is enabled and request bodies are actually rewritten.
	if hasReqRewrite && bodySize > 0 && len(reqBodyRewrites) > 0 && req.Body != nil {
		origReqBody, restored := borrowBodyPrefix(req.Body, bodySize)
		req.Body = restored
		ro.HTTP.OriginalRequest.Body = origReqBody
	}

	// Rewrite request body before wrapping for recording,
	// so the recorder sees the rewritten content.
	if err = rewriteReqBody(ctx, req, reqBodyRewrites...); err != nil {
		log.Errorf("rewrite request body: %v", err)
		return
	}

	if bodySize > 0 && req.Body != nil {
		reqBody := xhttp.NewBody(req.Body, bodySize)
		req.Body = reqBody
		err = req.Write(cc)
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	} else {
		err = req.Write(cc)
	}

	if err != nil {
		res.Write(rw)
		return
	}

	br := bufio.NewReader(cc)
	var resp *http.Response
	for {
		xio.SetReadDeadline(cc, time.Now().Add(ho.readTimeout))
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			log.Errorf("read response: %v", err)
			res.Write(rw)
			return
		}
		if resp.StatusCode == http.StatusContinue {
			resp.Write(rw)
			resp.Body.Close()
			continue
		}

		break
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	if hasRespRewrite {
		ro.HTTP.OriginalResponse = &xrecorder.HTTPResponseRecorderObject{
			ContentLength: resp.ContentLength,
			Header:        resp.Header.Clone(),
		}
	}

	// Reminder: apply responseHeader AFTER body rewrite, not before —
	// if responseHeader overrides Content-Type, the rewrite must first
	// read the original upstream Content-Type to decide
	// streaming vs non-streaming.

	ro.HTTP.StatusCode = resp.StatusCode

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(ctx, rw, cc, req, resp, ro, log)
		return
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = req.ProtoMajor
		resp.ProtoMinor = req.ProtoMinor
	}

	if !ho.httpKeepalive {
		resp.Header.Set("Connection", "close")
	}

	// Snapshot the original response body before rewriting, restoring it via
	// MultiReader so the body is read from upstream only once.
	if hasRespRewrite && bodySize > 0 && len(respBodyRewrites) > 0 {
		origRespBody, restored := borrowBodyPrefix(resp.Body, bodySize)
		resp.Body = restored
		ro.HTTP.OriginalResponse.Body = origRespBody
	}

	if err = rewriteRespBody(ctx, resp, respBodyRewrites...); err != nil {
		log.Errorf("rewrite body: %v", err)
		return
	}

	// Apply response header overrides after body rewrite so Content-Type
	// doesn't affect rewriteRespBody's streaming/non-streaming decision.
	if len(responseHeader) > 0 {
		if resp.Header == nil {
			resp.Header = http.Header{}
		}
		for k, v := range responseHeader {
			resp.Header.Set(k, v)
		}
	}
	ro.HTTP.Response.Header = resp.Header.Clone()
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if bodySize > 0 {
		respBody := xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
		err = resp.Write(rw)
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	} else {
		err = resp.Write(rw)
	}

	if err != nil {
		log.Errorf("write response: %v", err)
		return
	}

	if resp.ContentLength >= 0 {
		shouldClose = resp.Close
	}

	return
}
