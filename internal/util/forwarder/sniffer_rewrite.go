package forwarder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
)

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (h *Sniffer) handleUpgradeResponse(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && h.Websocket {
		return h.sniffingWebsocketFrame(ctx, rw, cc, ro, log)
	}

	return xnet.Pipe(ctx, rw, cc)
}

func rewriteRespBody(ctx context.Context, resp *http.Response, rewrites ...chain.HTTPBodyRewriteSettings) error {
	if resp == nil {
		return nil
	}
	uri := ""
	if resp.Request != nil {
		uri = resp.Request.RequestURI
	}
	rb, err := newRewriteBody(ctx, resp.Body, rewrites,
		resp.Header.Get("Content-Type"),
		resp.Header.Get("Content-Encoding"),
		resp.ContentLength, "response", uri)
	if err != nil {
		return err
	}
	if rb == nil {
		return nil
	}
	resp.Body = rb
	if !rb.streaming && rb.contentLength >= 0 {
		resp.ContentLength = rb.contentLength
		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
	}
	return nil
}

func drainBody(b io.ReadCloser) (body []byte, err error) {
	if b == nil || b == http.NoBody {
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

func rewriteReqBody(ctx context.Context, req *http.Request, rewrites ...chain.HTTPBodyRewriteSettings) error {
	if req == nil {
		return nil
	}
	rb, err := newRewriteBody(ctx, req.Body, rewrites,
		req.Header.Get("Content-Type"),
		req.Header.Get("Content-Encoding"),
		req.ContentLength, "request", req.RequestURI)
	if err != nil {
		return err
	}
	if rb == nil {
		return nil
	}
	req.Body = rb
	if !rb.streaming && rb.contentLength >= 0 {
		req.ContentLength = rb.contentLength
		req.TransferEncoding = nil
		req.Header.Del("Transfer-Encoding")
	}
	return nil
}

