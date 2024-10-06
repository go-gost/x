package sniffing

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http2"
)

const (
	// Default max body size to record.
	DefaultBodySize = 1024 * 1024 // 1MB
)

var (
	DefaultCertPool = tls_util.NewMemoryCertPool()
)

type Sniffer struct {
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
	DialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)

	Recorder        recorder.Recorder
	RecorderOptions *recorder.Options
	RecorderObject  *xrecorder.HandlerRecorderObject

	// MITM TLS termination
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
	NegotiatedProtocol string
	CertPool           tls_util.CertPool
	MitmBypass         bypass.Bypass

	ReadTimeout time.Duration
	Log         logger.Logger
}

func (h *Sniffer) HandleHTTP(ctx context.Context, conn net.Conn) error {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	if h.Log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		h.Log.Trace(string(dump))
	}

	ro := h.RecorderObject
	host := req.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
		}
		ro.Host = host

		h.Log = h.Log.WithFields(map[string]any{
			"host": host,
		})
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		const expectedBody = "SM\r\n\r\n"

		buf := make([]byte, len(expectedBody))
		n, err := io.ReadFull(br, buf)
		if err != nil {
			return fmt.Errorf("h2: error reading client preface: %s", err)
		}
		if string(buf[:n]) != expectedBody {
			return errors.New("h2: invalid client preface")
		}

		ro.Time = time.Time{}

		h2s := &http2.Server{}
		h2s.ServeConn(xnet.NewReadWriteConn(br, conn, conn), &http2.ServeConnOpts{
			Context:          ctx,
			SawClientPreface: true,
			Handler: &h2Handler{
				Client: &http.Client{
					Transport: &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
							if dial := h.DialTLS; dial != nil {
								return dial(ctx, network, addr, cfg)
							}

							cc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
							if err != nil {
								return nil, err
							}

							cc = tls.Client(cc, cfg)
							return cc, nil
						},
					},
				},
				Sniffer: h,
			},
		})
		return nil
	}

	dial := h.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, conn, cc, req)
	if err != nil || shouldClose {
		return err
	}

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if h.Log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpRequest(req, false)
			h.Log.Trace(string(dump))
		}

		if shouldClose, err := h.httpRoundTrip(ctx, conn, cc, req); err != nil || shouldClose {
			return err
		}
	}
}

func (h *Sniffer) httpRoundTrip(ctx context.Context, rw net.Conn, cc io.ReadWriter, req *http.Request) (close bool, err error) {
	close = true

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.RecorderObject

	ro.Time = time.Now()
	h.Log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.AddTrafficField(rw); err != nil {
			h.Log.Errorf("error adding traffic field: %s", err)
		}
		if err := ro.Record(ctx, h.Recorder); err != nil {
			h.Log.Errorf("record: %v", err)
		}

		h.Log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
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

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var reqBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = DefaultBodySize
			}
			reqBody = xhttp.NewBody(req.Body, maxSize)
			req.Body = reqBody
		}
	}

	if err = req.Write(cc); err != nil {
		return
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		h.Log.Errorf("read response: %v", err)
		return
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if h.Log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		h.Log.Trace(string(dump))
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = req.ProtoMajor
		resp.ProtoMinor = req.ProtoMinor
	}

	var respBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		maxSize := opts.MaxBodySize
		if maxSize <= 0 {
			maxSize = DefaultBodySize
		}
		respBody = xhttp.NewBody(resp.Body, maxSize)
		resp.Body = respBody
	}

	if err = resp.Write(rw); err != nil {
		h.Log.Errorf("write response: %v", err)
		return
	}

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if req.Header.Get("Upgrade") == "websocket" {
		xnet.Transport(rw, cc)
	}

	return resp.Close, nil
}

func (h *Sniffer) HandleTLS(ctx context.Context, conn net.Conn) error {
	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro := h.RecorderObject
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

	dial := h.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	if h.Certificate != nil && h.PrivateKey != nil &&
		len(clientHello.SupportedProtos) > 0 && (clientHello.SupportedProtos[0] == "h2" || clientHello.SupportedProtos[0] == "http/1.1") {
		if host == "" {
			host = ro.Host
		}
		if h.MitmBypass == nil || !h.MitmBypass.Contains(ctx, "tcp", host) {
			return h.terminateTLS(ctx, xnet.NewReadWriteConn(io.MultiReader(buf, conn), conn, conn), cc, clientHello)
		}
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
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

	h.Log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	xnet.Transport(conn, cc)
	h.Log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return err
}

func (h *Sniffer) terminateTLS(ctx context.Context, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo) error {
	ro := h.RecorderObject

	nextProtos := clientHello.SupportedProtos
	if h.NegotiatedProtocol != "" {
		nextProtos = []string{h.NegotiatedProtocol}
	}

	cfg := &tls.Config{
		ServerName:   clientHello.ServerName,
		NextProtos:   nextProtos,
		CipherSuites: clientHello.CipherSuites,
	}
	if cfg.ServerName == "" {
		cfg.InsecureSkipVerify = true
	}
	clientConn := tls.Client(cc, cfg)
	if err := clientConn.HandshakeContext(ctx); err != nil {
		return err
	}

	cs := clientConn.ConnectionState()
	ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
	ro.TLS.Proto = cs.NegotiatedProtocol
	ro.TLS.Version = tls_util.Version(cs.Version).String()

	host := cfg.ServerName
	if host == "" {
		if host = cs.PeerCertificates[0].Subject.CommonName; host == "" {
			host = ro.Host
		}
	}
	if h, _, _ := net.SplitHostPort(host); h != "" {
		host = h
	}

	negotiatedProtocol := cs.NegotiatedProtocol
	if h.NegotiatedProtocol != "" {
		negotiatedProtocol = h.NegotiatedProtocol
	}
	nextProtos = nil
	if negotiatedProtocol != "" {
		nextProtos = []string{negotiatedProtocol}
	}

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, err := certPool.Get(serverName)
			if cert == nil {
				cert, err = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
			}
			if err != nil {
				return nil, err
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	if err := serverConn.HandshakeContext(ctx); err != nil {
		return err
	}

	sniffer := &Sniffer{}
	*sniffer = *h

	sniffer.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return clientConn, nil
	}
	sniffer.DialTLS = func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
		return clientConn, nil
	}
	return sniffer.HandleHTTP(ctx, serverConn)
}

type h2Handler struct {
	Client  *http.Client
	Sniffer *Sniffer
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.Sniffer.Log

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.Sniffer.RecorderObject
	ro.Time = time.Now()

	var err error
	log.Infof("%s <-> %s", ro.RemoteAddr, r.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.Record(r.Context(), h.Sniffer.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
		}).Infof("%s >-< %s", ro.RemoteAddr, r.Host)
	}()

	if clientIP := xhttp.GetClientIP(r); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   r.Host,
		Proto:  r.Proto,
		Scheme: "https",
		Method: r.Method,
		URI:    r.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: r.ContentLength,
			Header:        r.Header.Clone(),
		},
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

	url := r.URL
	url.Scheme = "https"
	url.Host = r.Host
	req := &http.Request{
		Method:        r.Method,
		URL:           url,
		Host:          r.Host,
		Header:        r.Header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       r.Trailer,
	}

	var reqBody *xhttp.Body
	if opts := h.Sniffer.RecorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = DefaultBodySize
			}
			reqBody = xhttp.NewBody(req.Body, maxSize)
			req.Body = reqBody
		}
	}

	resp, err := h.Client.Do(req.WithContext(r.Context()))
	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusServiceUnavailable)
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

	h.setHeader(w, resp.Header)
	w.WriteHeader(resp.StatusCode)

	var respBody *xhttp.Body
	if opts := h.Sniffer.RecorderOptions; opts != nil && opts.HTTPBody {
		maxSize := opts.MaxBodySize
		if maxSize <= 0 {
			maxSize = DefaultBodySize
		}
		respBody = xhttp.NewBody(resp.Body, maxSize)
		resp.Body = respBody
	}

	io.Copy(w, resp.Body)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}
}

func (h *h2Handler) setHeader(w http.ResponseWriter, header http.Header) {
	for k, v := range header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
}
