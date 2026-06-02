package relay

import (
	"testing"
	"time"

	core_metadata "github.com/go-gost/core/metadata"
	xmetadata "github.com/go-gost/x/metadata"
)

func TestParseMetadata_Defaults(t *testing.T) {
	h := &relayHandler{}
	err := h.parseMetadata(xmetadata.NewMetadata(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 15*time.Second {
		t.Errorf("readTimeout = %v, want 15s", h.md.readTimeout)
	}
	if h.md.enableBind {
		t.Error("enableBind = true, want false")
	}
	if h.md.noDelay {
		t.Error("noDelay = true, want false")
	}
	if h.md.hash != "" {
		t.Errorf("hash = %q, want empty", h.md.hash)
	}
	if h.md.udpBufferSize != 0 {
		t.Errorf("udpBufferSize = %d, want 0", h.md.udpBufferSize)
	}
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("observerPeriod = %v, want 5s", h.md.observerPeriod)
	}
	if h.md.observerResetTraffic {
		t.Error("observerResetTraffic = true, want false")
	}
	if h.md.sniffing {
		t.Error("sniffing = true, want false")
	}
	if h.md.muxCfg == nil {
		t.Fatal("muxCfg = nil, want non-nil")
	}
	// Note: relay handler does NOT default muxCfg.Version or MaxStreamBuffer
	// at parseMetadata time. Those defaults are in the tunnel handler only.
}

func TestParseMetadata_ReadTimeout(t *testing.T) {
	tests := []struct {
		name  string
		input core_metadata.Metadata
		want  time.Duration
	}{
		{"zero", testMD(map[string]any{"readTimeout": 0}), 15 * time.Second},
		{"string 30s", testMD(map[string]any{"readTimeout": "30s"}), 30 * time.Second},
		{"int seconds", testMD(map[string]any{"readTimeout": 10}), 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &relayHandler{}
			h.parseMetadata(tt.input)
			if h.md.readTimeout != tt.want {
				t.Errorf("readTimeout = %v, want %v", h.md.readTimeout, tt.want)
			}
		})
	}
}

func TestParseMetadata_UDPBufferSize(t *testing.T) {
	tests := []struct {
		name  string
		input core_metadata.Metadata
		want  int
	}{
		{"zero", testMD(nil), 0},
		{"udp.bufferSize", testMD(map[string]any{"udp.bufferSize": 4096}), 4096},
		{"udpBufferSize alias", testMD(map[string]any{"udpBufferSize": 8192}), 8192},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &relayHandler{}
			h.parseMetadata(tt.input)
			if h.md.udpBufferSize != tt.want {
				t.Errorf("udpBufferSize = %d, want %d", h.md.udpBufferSize, tt.want)
			}
		})
	}
}

func TestParseMetadata_Bind(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{"bind": true}))
	if !h.md.enableBind {
		t.Error("enableBind = false, want true")
	}
}

func TestParseMetadata_NoDelay(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{"nodelay": true}))
	if !h.md.noDelay {
		t.Error("noDelay = false, want true")
	}
}

func TestParseMetadata_Hash(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{"hash": "host"}))
	if h.md.hash != "host" {
		t.Errorf("hash = %q, want host", h.md.hash)
	}
}

func TestParseMetadata_MuxConfig(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{
		"mux.version":           3,
		"mux.keepaliveInterval": "10s",
		"mux.keepaliveDisabled": true,
		"mux.keepaliveTimeout":  "5s",
		"mux.maxFrameSize":      4096,
		"mux.maxReceiveBuffer":  8192,
		"mux.maxStreamBuffer":   65536,
	}))
	if h.md.muxCfg.Version != 3 {
		t.Errorf("muxCfg.Version = %d, want 3", h.md.muxCfg.Version)
	}
	if h.md.muxCfg.KeepAliveInterval != 10*time.Second {
		t.Errorf("muxCfg.KeepAliveInterval = %v, want 10s", h.md.muxCfg.KeepAliveInterval)
	}
	if !h.md.muxCfg.KeepAliveDisabled {
		t.Error("muxCfg.KeepAliveDisabled = false, want true")
	}
	if h.md.muxCfg.KeepAliveTimeout != 5*time.Second {
		t.Errorf("muxCfg.KeepAliveTimeout = %v, want 5s", h.md.muxCfg.KeepAliveTimeout)
	}
	if h.md.muxCfg.MaxFrameSize != 4096 {
		t.Errorf("muxCfg.MaxFrameSize = %d, want 4096", h.md.muxCfg.MaxFrameSize)
	}
	if h.md.muxCfg.MaxReceiveBuffer != 8192 {
		t.Errorf("muxCfg.MaxReceiveBuffer = %d, want 8192", h.md.muxCfg.MaxReceiveBuffer)
	}
	if h.md.muxCfg.MaxStreamBuffer != 65536 {
		t.Errorf("muxCfg.MaxStreamBuffer = %d, want 65536", h.md.muxCfg.MaxStreamBuffer)
	}
}

func TestParseMetadata_Observer(t *testing.T) {
	tests := []struct {
		name       string
		input      core_metadata.Metadata
		wantPeriod time.Duration
		wantReset  bool
	}{
		{"defaults", testMD(nil), 5 * time.Second, false},
		{"custom period", testMD(map[string]any{"observePeriod": "10s"}), 10 * time.Second, false},
		{"clamped below 1s", testMD(map[string]any{"observePeriod": "500ms"}), time.Second, false},
		{"alias observer.period", testMD(map[string]any{"observer.period": "3s"}), 3 * time.Second, false},
		{"alias observer.observePeriod", testMD(map[string]any{"observer.observePeriod": "7s"}), 7 * time.Second, false},
		{"reset traffic", testMD(map[string]any{"observer.resetTraffic": true}), 5 * time.Second, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &relayHandler{}
			h.parseMetadata(tt.input)
			if h.md.observerPeriod != tt.wantPeriod {
				t.Errorf("observerPeriod = %v, want %v", h.md.observerPeriod, tt.wantPeriod)
			}
			if h.md.observerResetTraffic != tt.wantReset {
				t.Errorf("observerResetTraffic = %v, want %v", h.md.observerResetTraffic, tt.wantReset)
			}
		})
	}
}

func TestParseMetadata_Sniffing(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{
		"sniffing":                   true,
		"sniffing.timeout":           "2s",
		"sniffing.websocket":         true,
		"sniffing.websocket.sampleRate": 0.5,
	}))
	if !h.md.sniffing {
		t.Error("sniffing = false, want true")
	}
	if h.md.sniffingTimeout != 2*time.Second {
		t.Errorf("sniffingTimeout = %v, want 2s", h.md.sniffingTimeout)
	}
	if !h.md.sniffingWebsocket {
		t.Error("sniffingWebsocket = false, want true")
	}
	if h.md.sniffingWebsocketSampleRate != 0.5 {
		t.Errorf("sniffingWebsocketSampleRate = %v, want 0.5", h.md.sniffingWebsocketSampleRate)
	}
}

func TestParseMetadata_LimiterRefresh(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{
		"limiter.refreshInterval": "30s",
		"limiter.cleanupInterval": "60s",
	}))
	if h.md.limiterRefreshInterval != 30*time.Second {
		t.Errorf("limiterRefreshInterval = %v, want 30s", h.md.limiterRefreshInterval)
	}
	if h.md.limiterCleanupInterval != 60*time.Second {
		t.Errorf("limiterCleanupInterval = %v, want 60s", h.md.limiterCleanupInterval)
	}
}

func TestParseMetadata_Mitm(t *testing.T) {
	t.Run("not set", func(t *testing.T) {
		h := &relayHandler{}
		err := h.parseMetadata(testMD(nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if h.md.certificate != nil {
			t.Error("certificate should be nil")
		}
		if h.md.privateKey != nil {
			t.Error("privateKey should be nil")
		}
	})

	t.Run("cert file not found", func(t *testing.T) {
		h := &relayHandler{}
		err := h.parseMetadata(testMD(map[string]any{
			"mitm.certFile": "/nonexistent/cert.pem",
			"mitm.keyFile":  "/nonexistent/key.pem",
		}))
		if err == nil {
			t.Error("expected error for nonexistent cert file")
		}
	})

	t.Run("alpn set", func(t *testing.T) {
		h := &relayHandler{}
		h.parseMetadata(testMD(map[string]any{"mitm.alpn": "h2,http/1.1"}))
		if h.md.alpn != "h2,http/1.1" {
			t.Errorf("alpn = %q, want h2,http/1.1", h.md.alpn)
		}
	})
}

func TestParseMetadata_ObserverPeriodDefaultsTo5s(t *testing.T) {
	h := &relayHandler{}
	h.parseMetadata(testMD(map[string]any{"observePeriod": 0}))
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("observerPeriod = %v, want 5s", h.md.observerPeriod)
	}
}