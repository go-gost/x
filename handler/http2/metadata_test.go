package http2

import (
	"testing"
	"time"
)

func TestParseMetadata_ProbeResistance(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{
		"probeResist": "code:403",
		"knock":       "example.com,foo.com",
	})
	h.parseMetadata(md)

	pr := h.md.probeResistance
	if pr == nil {
		t.Fatal("probeResistance not set")
	}
	if pr.Type != "code" {
		t.Errorf("type = %q, want %q", pr.Type, "code")
	}
	if pr.Value != "403" {
		t.Errorf("value = %q, want %q", pr.Value, "403")
	}
	if pr.Knock != "example.com,foo.com" {
		t.Errorf("knock = %q, want %q", pr.Knock, "example.com,foo.com")
	}
}

func TestParseMetadata_Header(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{
		"header": map[string]any{"X-Custom": "value1", "X-Other": "value2"},
	})
	h.parseMetadata(md)

	if h.md.header.Get("X-Custom") != "value1" {
		t.Errorf("X-Custom = %q, want %q", h.md.header.Get("X-Custom"), "value1")
	}
	if h.md.header.Get("X-Other") != "value2" {
		t.Errorf("X-Other = %q, want %q", h.md.header.Get("X-Other"), "value2")
	}
}

func TestParseMetadata_Hash(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{"hash": "host"})
	h.parseMetadata(md)

	if h.md.hash != "host" {
		t.Errorf("hash = %q, want %q", h.md.hash, "host")
	}
}

func TestParseMetadata_ObserverDefaults(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{})
	h.parseMetadata(md)

	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("observerPeriod = %v, want 5s", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverPeriodClamped(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{"observePeriod": "100ms"})
	h.parseMetadata(md)

	if h.md.observerPeriod != time.Second {
		t.Errorf("observerPeriod = %v, want 1s (clamped)", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverResetTraffic(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{"observer.resetTraffic": true})
	h.parseMetadata(md)

	if !h.md.observerResetTraffic {
		t.Error("observerResetTraffic = false, want true")
	}
}

func TestParseMetadata_LimiterIntervals(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{
		"limiter.refreshInterval": "30s",
		"limiter.cleanupInterval": "60s",
	})
	h.parseMetadata(md)

	if h.md.limiterRefreshInterval != 30*time.Second {
		t.Errorf("limiterRefreshInterval = %v, want 30s", h.md.limiterRefreshInterval)
	}
	if h.md.limiterCleanupInterval != 60*time.Second {
		t.Errorf("limiterCleanupInterval = %v, want 60s", h.md.limiterCleanupInterval)
	}
}

func TestParseMetadata_HTTPHeaderAlias(t *testing.T) {
	h := newTestHandler()

	md := testMD(map[string]any{
		"http.header": map[string]any{"X-Alias": "value"},
	})
	h.parseMetadata(md)

	if h.md.header.Get("X-Alias") != "value" {
		t.Errorf("X-Alias = %q, want %q", h.md.header.Get("X-Alias"), "value")
	}
}
