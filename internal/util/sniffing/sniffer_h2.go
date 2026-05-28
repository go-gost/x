package sniffing

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xhttp "github.com/go-gost/x/internal/net/http"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http2"
)

// serveH2 handles HTTP/2 connections by reading the client preface and
// proxying requests through an http2.Transport.
func (h *Sniffer) serveH2(ctx context.Context, network string, conn net.Conn, ho *HandleOptions) error {
	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return fmt.Errorf("h2: error reading client preface: %s", err)
	}
	if string(buf[:n]) != expectedBody {
		return errors.New("h2: invalid client preface")
	}

	ro := ho.recorderObject
	log := ho.log

	ro.Time = time.Time{}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, nw, addr string, cfg *tls.Config) (net.Conn, error) {
			if dial := ho.dialTLS; dial != nil {
				return dial(ctx, network, addr, cfg)
			}

			cc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
			ro.SrcAddr = cc.LocalAddr().String()
			ro.DstAddr = cc.RemoteAddr().String()

			cc = tls.Client(cc, cfg)
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context:          ctx,
		SawClientPreface: true,
		Handler: &h2Handler{
			transport:       tr,
			recorder:        h.Recorder,
			recorderOptions: h.RecorderOptions,
			recorderObject:  ro,
			log:             log,
		},
	})
	return nil
}

// h2Handler is an http.Handler that proxies HTTP/2 requests through an
// http2.Transport while recording request and response metadata.
type h2Handler struct {
	transport       http.RoundTripper
	recorder        recorder.Recorder
	recorderOptions *recorder.Options
	recorderObject  *xrecorder.HandlerRecorderObject
	log             logger.Logger
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.recorderObject
	ro.Time = time.Now()

	var err error
	log.Infof("%s <-> %s", ro.RemoteAddr, r.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if rerr := ro.Record(r.Context(), h.recorder); rerr != nil {
			log.Errorf("record: %v", rerr)
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
	if bodySize := ClampBodySize(h.recorderOptions); bodySize > 0 && req.Body != nil {
		reqBody = xhttp.NewBody(req.Body, bodySize)
		req.Body = reqBody
	}

	resp, respErr := h.transport.RoundTrip(req.WithContext(r.Context()))
	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}
	err = respErr
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

	if bodySize := ClampBodySize(h.recorderOptions); bodySize > 0 {
		respBody := xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
		io.Copy(w, resp.Body)
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	} else {
		io.Copy(w, resp.Body)
	}
}

func (h *h2Handler) setHeader(w http.ResponseWriter, header http.Header) {
	for k, v := range header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
}
