package forwarder

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/rewriter"
)

// headerRewriter is a rewriter.Rewriter that records the metadata it receives.
type headerRewriter struct {
	cb       func(b []byte) []byte
	called   bool
	metadata map[string]any
}

func (m *headerRewriter) Rewrite(_ context.Context, b []byte, opts ...rewriter.RewriteOption) ([]byte, error) {
	m.called = true
	var ro rewriter.RewriteOptions
	for _, o := range opts {
		o(&ro)
	}
	if md, ok := ro.Metadata.(map[string]any); ok {
		m.metadata = md
	}
	if m.cb != nil {
		return m.cb(b), nil
	}
	return b, nil
}

func compileHeaderRewrite(name, match, replacement string) chain.HTTPHeaderRewriteSettings {
	var n, p *regexp.Regexp
	if name != "" {
		n = regexp.MustCompile(name)
	}
	if match != "" {
		p = regexp.MustCompile(match)
	}
	return chain.HTTPHeaderRewriteSettings{
		Name:        n,
		Pattern:     p,
		Replacement: []byte(replacement),
	}
}

func TestRewriteHeaderBlock_Regex(t *testing.T) {
	t.Run("location rewrite", func(t *testing.T) {
		h := http.Header{"Location": {"https://github.com/foo"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{compileHeaderRewrite(`(?i)^location$`, `https://(github\.com)`, `https://127.0.0.1:8080/$1`)},
			"response", "/")
		if err != nil {
			t.Fatal(err)
		}
		if got := h.Get("Location"); got != "https://127.0.0.1:8080/github.com/foo" {
			t.Errorf("Location = %q", got)
		}
	})

	t.Run("multi-value set-cookie per-value", func(t *testing.T) {
		h := http.Header{
			"Set-Cookie": {
				"a=1; Domain=.github.com; Path=/",
				"b=2; Domain=github.com",
			},
		}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{compileHeaderRewrite(`(?i)^set-cookie$`, `Domain=\.?github\.com;?\s*`, ``)},
			"response", "/")
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range h.Values("Set-Cookie") {
			if regexp.MustCompile(`Domain`).MatchString(v) {
				t.Errorf("Set-Cookie still has Domain: %q", v)
			}
		}
	})

	t.Run("delete header on empty value", func(t *testing.T) {
		h := http.Header{"Content-Security-Policy": {"default-src 'self'"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{compileHeaderRewrite(`(?i)^content-security-policy$`, `.*`, ``)},
			"response", "/")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := h["Content-Security-Policy"]; ok {
			t.Errorf("header should be deleted, got %v", h)
		}
	})

	t.Run("mixed-case name matching", func(t *testing.T) {
		h := http.Header{"Referer": {"https://127.0.0.1:8080/github.com/x"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{compileHeaderRewrite(`(?i)^(referer|origin)$`, `.*`, ``)},
			"request", "/github.com/x")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := h["Referer"]; ok {
			t.Errorf("Referer should be deleted, got %v", h)
		}
	})

	t.Run("name no-match leaves header untouched", func(t *testing.T) {
		h := http.Header{"X-Forwarded-Host": {"example.com"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{compileHeaderRewrite(`(?i)^location$`, `.*`, ``)},
			"response", "/")
		if err != nil {
			t.Fatal(err)
		}
		if got := h.Get("X-Forwarded-Host"); got != "example.com" {
			t.Errorf("X-Forwarded-Host = %q, want untouched", got)
		}
	})
}

func TestRewriteHeaderBlock_Plugin(t *testing.T) {
	t.Run("round-trip with in-place replacement", func(t *testing.T) {
		rw := &headerRewriter{cb: func(b []byte) []byte {
			return []byte("X-Added: yes\r\nLocation: https://127.0.0.1:8080/github.com/x\r\n\r\n")
		}}
		h := http.Header{"Location": {"https://github.com/x"}, "Keep-Me": {"v"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{{Rewriter: rw}},
			"response", "/github.com/x")
		if err != nil {
			t.Fatal(err)
		}
		if !rw.called {
			t.Fatal("rewriter not called")
		}
		if got := h.Get("Location"); got != "https://127.0.0.1:8080/github.com/x" {
			t.Errorf("Location = %q", got)
		}
		if got := h.Get("X-Added"); got != "yes" {
			t.Errorf("X-Added = %q", got)
		}
		if _, ok := h["Keep-Me"]; ok {
			t.Errorf("Keep-Me should be gone after plugin replaced the block, got %v", h)
		}
	})

	t.Run("metadata contains kind header", func(t *testing.T) {
		rw := &headerRewriter{}
		h := http.Header{"Location": {"https://github.com/x"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{{Rewriter: rw}},
			"response", "/github.com/x")
		if err != nil {
			t.Fatal(err)
		}
		if rw.metadata == nil {
			t.Fatal("metadata not captured")
		}
		if got := rw.metadata[MetaKeyKind]; got != KindHeader {
			t.Errorf("kind = %v, want %q", got, KindHeader)
		}
		if got := rw.metadata[MetaKeyDirection]; got != "response" {
			t.Errorf("direction = %v, want %q", got, "response")
		}
		if got := rw.metadata[MetaKeyURI]; got != "/github.com/x" {
			t.Errorf("uri = %v, want %q", got, "/github.com/x")
		}
	})

	t.Run("plugin output without trailing blank line", func(t *testing.T) {
		var got []byte
		rw := &headerRewriter{cb: func(b []byte) []byte {
			got = append([]byte(nil), b...)
			return []byte("Location: https://127.0.0.1:8080/github.com/x\r\n")
		}}
		h := http.Header{"Location": {"https://github.com/x"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{{Rewriter: rw}}, "response", "/")
		if err != nil {
			t.Fatalf("ReadMIMEHeader must not fail on a plugin block with no blank line: %v", err)
		}
		if !bytes.HasSuffix(got, []byte("\r\n\r\n")) {
			t.Errorf("plugin input missing trailing blank line: %q", got)
		}
		if v := h.Get("Location"); v != "https://127.0.0.1:8080/github.com/x" {
			t.Errorf("Location = %q", v)
		}
	})

	t.Run("name gate skips non-matching", func(t *testing.T) {
		rw := &headerRewriter{}
		h := http.Header{"X-Other": {"v"}}
		err := rewriteHeaderBlock(context.Background(), h,
			[]chain.HTTPHeaderRewriteSettings{{Name: regexp.MustCompile(`(?i)^location$`), Rewriter: rw}},
			"response", "/")
		if err != nil {
			t.Fatal(err)
		}
		if rw.called {
			t.Fatal("rewriter should be skipped when name does not match")
		}
	})
}

func TestRewriteMeta(t *testing.T) {
	t.Run("omits empty common fields", func(t *testing.T) {
		md := rewriteMeta("", "", "", "", nil)
		if len(md) != 0 {
			t.Errorf("md = %v, want empty", md)
		}
	})

	t.Run("includes kind and extras", func(t *testing.T) {
		md := rewriteMeta("s", "response", "/u", KindHeader, map[string]any{"sse_phase": "end"})
		if md[MetaKeySid] != "s" || md[MetaKeyDirection] != "response" || md[MetaKeyURI] != "/u" || md[MetaKeyKind] != KindHeader {
			t.Errorf("common fields wrong: %v", md)
		}
		if md["sse_phase"] != "end" {
			t.Errorf("extra missing: %v", md)
		}
	})
}

func TestRewriteReqRespHeader_NilGuard(t *testing.T) {
	if err := rewriteReqHeader(context.Background(), nil); err != nil {
		t.Errorf("rewriteReqHeader(nil) = %v", err)
	}
	if err := rewriteRespHeader(context.Background(), nil); err != nil {
		t.Errorf("rewriteRespHeader(nil) = %v", err)
	}
}
