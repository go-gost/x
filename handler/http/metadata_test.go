package http

import (
	"testing"
	"time"
)

func TestParseMetadata_Defaults(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if h.md.readTimeout != 15*time.Second {
		t.Errorf("got readTimeout %v, want 15s", h.md.readTimeout)
	}
	if h.md.proxyAgent != defaultProxyAgent {
		t.Errorf("got proxyAgent %q, want %q", h.md.proxyAgent, defaultProxyAgent)
	}
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("got observerPeriod %v, want 5s", h.md.observerPeriod)
	}
}

func TestParseMetadata_ReadTimeout(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"readTimeout": "30s"})); err != nil {
		t.Fatal(err)
	}
	if h.md.readTimeout != 30*time.Second {
		t.Errorf("got readTimeout %v, want 30s", h.md.readTimeout)
	}
}

func TestParseMetadata_NegativeReadTimeout(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"readTimeout": "-1"})); err != nil {
		t.Fatal(err)
	}
	if h.md.readTimeout != 0 {
		t.Errorf("got readTimeout %v, want 0 for negative value", h.md.readTimeout)
	}
}

func TestParseMetadata_IdleTimeout(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"idleTimeout": "60s"})); err != nil {
		t.Fatal(err)
	}
	if h.md.idleTimeout != 60*time.Second {
		t.Errorf("got idleTimeout %v, want 60s", h.md.idleTimeout)
	}
}

func TestParseMetadata_NegativeIdleTimeout(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"idleTimeout": "-1"})); err != nil {
		t.Fatal(err)
	}
	if h.md.idleTimeout != 0 {
		t.Errorf("got idleTimeout %v, want 0 for negative value", h.md.idleTimeout)
	}
}

func TestParseMetadata_Headers(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"http.header": map[string]any{
			"X-Custom": "value",
		},
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.header.Get("X-Custom") != "value" {
		t.Errorf("got header X-Custom=%q, want %q", h.md.header.Get("X-Custom"), "value")
	}
}

func TestParseMetadata_Keepalive(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"keepalive": "true"})); err != nil {
		t.Fatal(err)
	}
	if !h.md.keepalive {
		t.Error("expected keepalive to be true")
	}
}

func TestParseMetadata_Compression(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"compression": "true"})); err != nil {
		t.Fatal(err)
	}
	if !h.md.compression {
		t.Error("expected compression to be true")
	}
}

func TestParseMetadata_ProbeResistance(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"probeResist": "code:404",
		"knock":       "secret.example.com",
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.probeResistance == nil {
		t.Fatal("expected probeResistance to be set")
	}
	if h.md.probeResistance.Type != "code" {
		t.Errorf("got type %q, want %q", h.md.probeResistance.Type, "code")
	}
	if h.md.probeResistance.Value != "404" {
		t.Errorf("got value %q, want %q", h.md.probeResistance.Value, "404")
	}
	if h.md.probeResistance.Knock != "secret.example.com" {
		t.Errorf("got knock %q, want %q", h.md.probeResistance.Knock, "secret.example.com")
	}
}

func TestParseMetadata_ProbeResistance_KnockMulti(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"probeResist": "code:404",
		"knock":       " a.example.com , b.example.com ",
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.probeResistance == nil {
		t.Fatal("expected probeResistance to be set")
	}
	if h.md.probeResistance.Knock != " a.example.com , b.example.com " {
		t.Errorf("got knock %q, want raw comma-separated string", h.md.probeResistance.Knock)
	}
}

func TestParseMetadata_ProbeResistance_InvalidFormat(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"probeResist": "invalid"})); err != nil {
		t.Fatal(err)
	}
	// probeResist without colon is ignored
	if h.md.probeResistance != nil {
		t.Error("expected nil probeResistance for invalid format")
	}
}

func TestParseMetadata_UDP(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"udp":            "true",
		"udpBufferSize":  "4096",
	})); err != nil {
		t.Fatal(err)
	}
	if !h.md.enableUDP {
		t.Error("expected enableUDP to be true")
	}
	if h.md.udpBufferSize != 4096 {
		t.Errorf("got udpBufferSize %d, want 4096", h.md.udpBufferSize)
	}
}

func TestParseMetadata_Hash(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"hash": "host"})); err != nil {
		t.Fatal(err)
	}
	if h.md.hash != "host" {
		t.Errorf("got hash %q, want %q", h.md.hash, "host")
	}
}

func TestParseMetadata_ObserverPeriod(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"observePeriod": "10s"})); err != nil {
		t.Fatal(err)
	}
	if h.md.observerPeriod != 10*time.Second {
		t.Errorf("got observerPeriod %v, want 10s", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverPeriod_Minimum(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"observePeriod": "500ms"})); err != nil {
		t.Fatal(err)
	}
	if h.md.observerPeriod != time.Second {
		t.Errorf("got observerPeriod %v, want minimum 1s", h.md.observerPeriod)
	}
}

func TestParseMetadata_Sniffing(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"sniffing":                   "true",
		"sniffing.timeout":           "5s",
		"sniffing.websocket":         "true",
		"sniffing.websocket.sampleRate": "20.0",
	})); err != nil {
		t.Fatal(err)
	}
	if !h.md.sniffing {
		t.Error("expected sniffing to be true")
	}
	if h.md.sniffingTimeout != 5*time.Second {
		t.Errorf("got sniffingTimeout %v, want 5s", h.md.sniffingTimeout)
	}
	if !h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket to be true")
	}
	if h.md.sniffingWebsocketSampleRate != 20.0 {
		t.Errorf("got sampleRate %f, want 20.0", h.md.sniffingWebsocketSampleRate)
	}
}

func TestParseMetadata_ProxyAgent(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"proxyAgent": "custom/1.0"})); err != nil {
		t.Fatal(err)
	}
	if h.md.proxyAgent != "custom/1.0" {
		t.Errorf("got proxyAgent %q, want %q", h.md.proxyAgent, "custom/1.0")
	}
}

func TestParseMetadata_AuthBasicRealm(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"authBasicRealm": "myrealm"})); err != nil {
		t.Fatal(err)
	}
	if h.md.authBasicRealm != "myrealm" {
		t.Errorf("got realm %q, want %q", h.md.authBasicRealm, "myrealm")
	}
}

func TestParseMetadata_LimiterIntervals(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"limiter.refreshInterval": "30s",
		"limiter.cleanupInterval": "60s",
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.limiterRefreshInterval != 30*time.Second {
		t.Errorf("got refreshInterval %v, want 30s", h.md.limiterRefreshInterval)
	}
	if h.md.limiterCleanupInterval != 60*time.Second {
		t.Errorf("got cleanupInterval %v, want 60s", h.md.limiterCleanupInterval)
	}
}

func TestParseMetadata_ObserverResetTraffic(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"observer.resetTraffic": "true"})); err != nil {
		t.Fatal(err)
	}
	if !h.md.observerResetTraffic {
		t.Error("expected observer.resetTraffic to be true")
	}
}

func TestParseMetadata_MITM_Config(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"mitm.certFile": "/nonexistent.pem",
		"mitm.keyFile":  "/nonexistent.key",
	})); err == nil {
		t.Error("expected error for nonexistent cert/key files")
	}
}

func TestParseMetadata_MITM_ALPN(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"mitm.alpn": "h2",
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.alpn != "h2" {
		t.Errorf("got alpn %q, want h2", h.md.alpn)
	}
}

func TestParseMetadata_MITM_Bypass(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"mitm.bypass": "",
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.mitmBypass != nil {
		t.Error("expected nil mitmBypass for empty bypass name")
	}
}

func TestParseMetadata_ObserverPeriod_Zero(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"observePeriod": "0"})); err != nil {
		t.Fatal(err)
	}
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("got observerPeriod %v, want 5s (default for zero)", h.md.observerPeriod)
	}
}

func TestParseMetadata_Headers_AltKey(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{
		"header": map[string]any{
			"X-Custom": "value-from-alt-key",
		},
	})); err != nil {
		t.Fatal(err)
	}
	if h.md.header.Get("X-Custom") != "value-from-alt-key" {
		t.Errorf("got header X-Custom=%q, want value-from-alt-key", h.md.header.Get("X-Custom"))
	}
}

func TestParseMetadata_ProxyAgent_AltKey(t *testing.T) {
	h := &httpHandler{}
	if err := h.parseMetadata(testMD(map[string]any{"http.proxyAgent": "gost-alt/1.0"})); err != nil {
		t.Fatal(err)
	}
	if h.md.proxyAgent != "gost-alt/1.0" {
		t.Errorf("got proxyAgent %q, want gost-alt/1.0", h.md.proxyAgent)
	}
}
