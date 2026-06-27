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
	if resp == nil || len(rewrites) == 0 || resp.ContentLength <= 0 {
		return nil
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
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

		if rewrite.Rewriter != nil {
			body, err = rewrite.Rewriter.Rewrite(ctx, body)
			if err != nil {
				return err
			}
		} else if rewrite.Pattern != nil {
			body = rewrite.Pattern.ReplaceAll(body, rewrite.Replacement)
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

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
	if req == nil || len(rewrites) == 0 || req.Body == nil || req.ContentLength <= 0 {
		return nil
	}

	if encoding := req.Header.Get("Content-Encoding"); encoding != "" {
		return nil
	}

	body, err := drainBody(req.Body)
	if err != nil || body == nil {
		return err
	}

	contentType, _, _ := strings.Cut(req.Header.Get("Content-Type"), ";")
	for _, rewrite := range rewrites {
		rewriteType := rewrite.Type
		if rewriteType == "" {
			rewriteType = "text/html"
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, contentType) {
			continue
		}

		if rewrite.Rewriter != nil {
			body, err = rewrite.Rewriter.Rewrite(ctx, body)
			if err != nil {
				return err
			}
		} else if rewrite.Pattern != nil {
			body = rewrite.Pattern.ReplaceAll(body, rewrite.Replacement)
		}
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	return nil
}

