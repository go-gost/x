package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/rewriter"
	xctx "github.com/go-gost/x/ctx"
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

// rewriteHeaderBlock applies the header rewrite chain to h in place.
func rewriteHeaderBlock(ctx context.Context, h http.Header, rewrites []chain.HTTPHeaderRewriteSettings, direction, uri string) error {
	if len(rewrites) == 0 || h == nil {
		return nil
	}
	sid := xctx.SidFromContext(ctx).String()

	for _, rw := range rewrites {
		if rw.Rewriter != nil {
			// Plugin mode: gate on rw.Name matching any header name (nil Name
			// means "always invoke"), serialize the whole header block, and
			// parse the plugin's bytes back into the header.
			if rw.Name != nil && !anyHeaderNameMatch(h, rw.Name) {
				continue
			}
			var buf bytes.Buffer
			if err := h.Write(&buf); err != nil {
				return err
			}
			// http.Header.Write emits "Key: value\r\n" lines with no trailing
			// blank line; append one so ReadMIMEHeader can find the end.
			buf.WriteString("\r\n")
			md := rewriteMeta(sid, direction, uri, KindHeader, nil)
			rewritten, err := rw.Rewriter.Rewrite(ctx, buf.Bytes(), rewriter.MetadataRewriteOption(md))
			if err != nil {
				return err
			}
			// Tolerate a plugin that omits the trailing blank line.
			if !bytes.HasSuffix(rewritten, []byte("\r\n\r\n")) && !bytes.HasSuffix(rewritten, []byte("\n\n")) {
				rewritten = append(rewritten, '\r', '\n')
			}
			nh, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(rewritten))).ReadMIMEHeader()
			if err != nil {
				return err
			}
			// h is a map reference; replace its contents in place, not via
			// reassignment (which would only rebind the local variable).
			clear(h)
			for k, vs := range nh {
				h[k] = vs
			}
			continue
		}

		// Regex mode.
		if rw.Name == nil {
			continue
		}
		for name, values := range h {
			if !rw.Name.MatchString(strings.ToLower(name)) {
				continue
			}
			kept := values[:0]
			for _, v := range values {
				if rw.Pattern == nil {
					kept = append(kept, v)
					continue
				}
				if nv := rw.Pattern.ReplaceAllString(v, string(rw.Replacement)); nv != "" {
					kept = append(kept, nv)
				}
			}
			if len(kept) == 0 {
				h.Del(name)
			} else {
				h[name] = kept
			}
		}
	}
	return nil
}

func rewriteReqHeader(ctx context.Context, req *http.Request, rewrites ...chain.HTTPHeaderRewriteSettings) error {
	if req == nil {
		return nil
	}
	return rewriteHeaderBlock(ctx, req.Header, rewrites, "request", req.RequestURI)
}

func rewriteRespHeader(ctx context.Context, resp *http.Response, rewrites ...chain.HTTPHeaderRewriteSettings) error {
	if resp == nil {
		return nil
	}
	uri := ""
	if resp.Request != nil {
		uri = resp.Request.RequestURI
	}
	return rewriteHeaderBlock(ctx, resp.Header, rewrites, "response", uri)
}

// anyHeaderNameMatch reports whether any header name matches the regex.
func anyHeaderNameMatch(h http.Header, name *regexp.Regexp) bool {
	for k := range h {
		if name.MatchString(strings.ToLower(k)) {
			return true
		}
	}
	return false
}

