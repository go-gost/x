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

// AuthResult is returned by Authenticator.Authenticate. When OK is false,
// Response is the HTTP response to write to the client (407 or a probe-
// resistance decoy). When PipeTo is non-empty, the caller must dial the
// given address, pipe the raw request through it, and return immediately —
// the connection is consumed by host-mode probe resistance.
type AuthResult struct {
	ClientID string
	OK       bool
	Response *http.Response // non-nil when !OK (407 or probe-resistance decoy)
	PipeTo   string         // non-empty when pr.Type=="host"; caller dials+pipes
}

// Authenticator validates Proxy-Authorization headers and generates probe-
// resistance decoy responses on failure. It does not perform I/O — the
// caller is responsible for writing the returned response or dialling the
// PipeTo target.
type Authenticator struct {
	Auther    auth.Authenticator
	PR        *probeResistance
	Realm     string
	Service   string                                         // service name passed to auth.WithService
	WebClient func(string) (*http.Response, error)           // injectable for tests; defaults to http.Get
	Log       logger.Logger
}

// Authenticate validates the client's credentials and returns an AuthResult.
// When no Auther is configured, all requests are anonymous (OK=true).
// On auth failure, if probe resistance is configured, a decoy response is
// built; otherwise a standard 407 Proxy-Auth-Required is returned.
//
// The "host" probe resistance strategy is signalled via PipeTo rather than
// handled inline — the caller must dial the PipeTo address and pipe the
// raw request through it. All other strategies produce a Response.
func (a *Authenticator) Authenticate(ctx context.Context, req *http.Request) *AuthResult {
	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if a.Auther == nil {
		return &AuthResult{OK: true}
	}
	if id, ok := a.Auther.Authenticate(ctx, u, p, auth.WithService(a.optionsService())); ok {
		return &AuthResult{OK: true, ClientID: id}
	}

	pr := a.PR
	if pr != nil && (pr.Knock == "" || !knockMatch(req.URL.Hostname(), pr.Knock)) {
		return a.probeResistanceResponse(req)
	}

	return a.build407Response(req)
}

func (a *Authenticator) optionsService() string {
	return a.Service
}

func (a *Authenticator) probeResistanceResponse(req *http.Request) *AuthResult {
	pr := a.PR
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
		StatusCode:    http.StatusServiceUnavailable,
	}

	switch pr.Type {
	case "code":
		if code, err := strconv.Atoi(pr.Value); err == nil {
			resp.StatusCode = code
		} else if a.Log != nil {
			a.Log.Warnf("invalid probe resistance code: %s", pr.Value)
		}
	case "web":
		url := pr.Value
		if !strings.HasPrefix(url, "http") {
			url = "http://" + url
		}
		webClient := a.WebClient
		if webClient == nil {
			webClient = httpGet
		}
		r, err := webClient(url)
		if err != nil {
			if a.Log != nil {
				a.Log.Error(err)
			}
			break
		}
		*resp = *r
	case "host":
		return &AuthResult{PipeTo: pr.Value}
	case "file":
		f, _ := os.Open(pr.Value)
		if f != nil {
			resp.StatusCode = http.StatusOK
			if finfo, _ := f.Stat(); finfo != nil {
				resp.ContentLength = finfo.Size()
			}
			resp.Header.Set("Content-Type", "text/html")
			resp.Body = f
		}
	}

	if resp.StatusCode == 0 {
		return a.build407Response(req)
	}

	if resp.StatusCode == http.StatusOK {
		resp.Header.Set("Connection", "keep-alive")
	}
	return &AuthResult{Response: resp}
}

func (a *Authenticator) build407Response(req *http.Request) *AuthResult {
	realm := defaultRealm
	if a.Realm != "" {
		realm = a.Realm
	}
	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: -1,
		StatusCode:    http.StatusProxyAuthRequired,
	}
	resp.Header.Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
	if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
		resp.Header.Set("Connection", "close")
		resp.Header.Set("Proxy-Connection", "close")
	}
	return &AuthResult{Response: resp}
}

// httpGet is the default web client used by probe-resistance "web" strategy.
func httpGet(url string) (*http.Response, error) {
	return (&http.Client{Timeout: 15 * time.Second}).Get(url)
}

// handleProbeResistanceHost dials the decoy host and relays the raw request
// and response bidirectionally. It is called by handleRequest when the
// Authenticator returns PipeTo != "". The connection is consumed.
func (h *httpHandler) handleProbeResistanceHost(ctx context.Context, conn net.Conn, req *http.Request, target string, log logger.Logger, resp *http.Response) error {
	cc, err := net.Dial("tcp", target)
	if err != nil {
		log.Error(err)
		resp.StatusCode = http.StatusServiceUnavailable
		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		return resp.Write(conn)
	}
	defer cc.Close()

	req.Write(cc)
	return xnet.Pipe(ctx, conn, cc, xnet.WithReadTimeout(h.md.idleTimeout))
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

// knockMatch reports whether hostname matches any entry in the
// comma-separated knock list. Matching is case-insensitive. An empty
// knock string returns false (no match).
func knockMatch(hostname, knock string) bool {
	if knock == "" {
		return false
	}
	for _, h := range strings.Split(knock, ",") {
		if strings.EqualFold(hostname, strings.TrimSpace(h)) {
			return true
		}
	}
	return false
}
