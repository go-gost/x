package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	xnet "github.com/go-gost/x/internal/net"
)

// authenticate verifies the client's Proxy-Authorization header against the
// configured Authenticator. When authentication fails and probe resistance
// is configured, a decoy response is returned to hide the proxy.
//
// Five probe resistance strategies are supported:
//
//   - "code": respond with a custom HTTP status code (e.g. "code:404").
//   - "web": fetch a URL and replay its response as the decoy.
//   - "host": forward the raw request to a decoy host and relay the reply.
//   - "file": serve a local file with Content-Type: text/html.
//   - knock: when pr.Knock is set, probe resistance only activates if the
//     request hostname does NOT match the knock address. Clients that know
//     the knock hostname get the normal 407 Proxy-Auth-Required.
//
// On success it returns the authenticated client ID. On failure it writes
// the response (407 or probe-resistance decoy) to conn and returns ok=false.
func (h *httpHandler) authenticate(ctx context.Context, conn net.Conn, req *http.Request, resp *http.Response, log logger.Logger) (id string, ok bool) {
	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if h.options.Auther == nil {
		return "", true
	}
	if id, ok = h.options.Auther.Authenticate(ctx, u, p, auth.WithService(h.options.Service)); ok {
		return
	}

	pr := h.md.probeResistance
	// Probe resistance activates on auth failure when:
	//   - pr.Knock is empty (always hide the proxy), OR
	//   - pr.Knock is set but the request hostname doesn't match (the client
	//     didn't "knock" on the right host — hide the proxy).
	// When pr.Knock matches the hostname, probe resistance is bypassed and
	// the normal 407 Proxy-Auth-Required is returned, revealing the proxy
	// only to clients that know the knock address.
	if pr != nil && (pr.Knock == "" || !strings.EqualFold(req.URL.Hostname(), pr.Knock)) {
		resp.StatusCode = http.StatusServiceUnavailable

		switch pr.Type {
		case "code":
			if code, err := strconv.Atoi(pr.Value); err == nil {
				resp.StatusCode = code
			} else {
				log.Warnf("invalid probe resistance code: %s", pr.Value)
			}
		case "web":
			url := pr.Value
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			client := &http.Client{Timeout: 15 * time.Second}
			r, err := client.Get(url)
			if err != nil {
				log.Error(err)
				break
			}
			// Replace resp content with the fetched web response.
			// Body is closed after writing in the caller.
			*resp = *r
		case "host":
			// Dial the decoy host and transparently relay the request/response.
			cc, err := net.Dial("tcp", pr.Value)
			if err != nil {
				log.Error(err)
				break
			}
			defer cc.Close()

			req.Write(cc)
			xnet.Pipe(ctx, conn, cc, xnet.WithReadTimeout(h.md.idleTimeout))
			return "", false
		case "file":
			f, _ := os.Open(pr.Value)
			if f != nil {
				defer f.Close()

				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Header.Set("Content-Type", "text/html")
				resp.Body = f
			}
		}
	}

	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if resp.StatusCode == 0 {
		// Normal 407 Proxy-Auth-Required response.
		realm := defaultRealm
		if h.md.authBasicRealm != "" {
			realm = h.md.authBasicRealm
		}
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
		if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
			// libcurl will keep sending auth requests on the same
			// connection, which we don't support yet. Force close.
			resp.Header.Set("Connection", "close")
			resp.Header.Set("Proxy-Connection", "close")
		}

		log.Debug("proxy authentication required")
	} else {
		// Probe resistance sent a non-407 status. For 200 OK file/web
		// responses, advertise keep-alive to appear like a normal server.
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err := resp.Write(conn); err != nil {
		log.Error("write auth response: ", err)
	}
	return
}

// checkRateLimit verifies that the remote address has not exceeded the
// configured connection rate limit. It extracts the host portion of addr
// and looks up the per-host limiter. Returns true if the connection is
// allowed or if no rate limiter is configured.
func (h *httpHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	if addr == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
