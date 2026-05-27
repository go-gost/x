package sniffing

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-gost/core/logger"
	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
)

// upgradeType extracts the Upgrade protocol from an HTTP header if the
// Connection header contains the "Upgrade" token.
func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// handleUpgradeResponse handles HTTP 101 Switching Protocols responses.
// It validates the upgrade type, writes the response, and either begins
// WebSocket frame sniffing or falls through to bidirectional copy.
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
