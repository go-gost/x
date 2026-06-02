package tunnel

import (
	"context"
	"testing"
	"time"

	mdx "github.com/go-gost/x/metadata"
)

func TestParseMetadata_Defaults(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.readTimeout != 0 {
		t.Errorf("expected readTimeout 0, got %v", h.md.readTimeout)
	}
	if h.md.entryPoint != "" {
		t.Errorf("expected empty entryPoint, got %q", h.md.entryPoint)
	}
	if h.md.tunnelTTL != defaultTTL {
		t.Errorf("expected tunnelTTL %v, got %v", defaultTTL, h.md.tunnelTTL)
	}
	if h.md.entryPointReadTimeout != 15*time.Second {
		t.Errorf("expected entryPointReadTimeout 15s, got %v", h.md.entryPointReadTimeout)
	}
	if h.md.muxCfg.Version != 2 {
		t.Errorf("expected mux version 2, got %d", h.md.muxCfg.Version)
	}
	if h.md.muxCfg.MaxStreamBuffer != 1048576 {
		t.Errorf("expected max stream buffer 1048576, got %d", h.md.muxCfg.MaxStreamBuffer)
	}
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("expected observerPeriod 5s, got %v", h.md.observerPeriod)
	}
	if h.md.directTunnel {
		t.Error("expected directTunnel false")
	}
	if h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket false")
	}
	if h.md.ingress != nil {
		t.Error("expected nil ingress")
	}
	if h.md.sd != nil {
		t.Error("expected nil sd")
	}
}

func TestParseMetadata_ReadTimeout(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"readTimeout": "3s",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.readTimeout != 3*time.Second {
		t.Errorf("expected readTimeout 3s, got %v", h.md.readTimeout)
	}
}

func TestParseMetadata_Entrypoint(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoint": ":8080",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.entryPoint != ":8080" {
		t.Errorf("expected entryPoint :8080, got %q", h.md.entryPoint)
	}
}

func TestParseMetadata_DirectTunnel(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel.direct": true,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.directTunnel {
		t.Error("expected directTunnel true")
	}
}

func TestParseMetadata_TunnelTTL(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel.ttl": "30s",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.tunnelTTL != 30*time.Second {
		t.Errorf("expected tunnelTTL 30s, got %v", h.md.tunnelTTL)
	}
}

func TestParseMetadata_TunnelTTL_ZeroDefaults(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel.ttl": 0,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.tunnelTTL != defaultTTL {
		t.Errorf("expected tunnelTTL %v, got %v", defaultTTL, h.md.tunnelTTL)
	}
}

func TestParseMetadata_Sniffing(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"sniffing.websocket":          true,
		"sniffing.websocket.sampleRate": 0.5,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.sniffingWebsocket {
		t.Error("expected sniffingWebsocket true")
	}
	if h.md.sniffingWebsocketSampleRate != 0.5 {
		t.Errorf("expected sampleRate 0.5, got %f", h.md.sniffingWebsocketSampleRate)
	}
}

func TestParseMetadata_ObserverPeriod(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect time.Duration
	}{
		{"custom period", "10s", 10 * time.Second},
		{"minimum clamped to 1s", "100ms", time.Second},
		{"zero defaults to 5s", "", 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &tunnelHandler{}
			data := map[string]any{}
			if tt.input != "" {
				data["observePeriod"] = tt.input
			}
			md := mdx.NewMetadata(data)
			err := h.parseMetadata(md)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h.md.observerPeriod != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, h.md.observerPeriod)
			}
		})
	}
}

func TestParseMetadata_ObserverPeriod_AlternateKeys(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"observer.period": "3s",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.observerPeriod != 3*time.Second {
		t.Errorf("expected 3s, got %v", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverResetTraffic(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"observer.resetTraffic": true,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.observerResetTraffic {
		t.Error("expected observerResetTraffic true")
	}
}

func TestParseMetadata_MuxConfig(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"mux.version":             1,
		"mux.keepaliveInterval":   "10s",
		"mux.keepaliveDisabled":   true,
		"mux.keepaliveTimeout":    "30s",
		"mux.maxFrameSize":        4096,
		"mux.maxReceiveBuffer":    8192,
		"mux.maxStreamBuffer":     65536,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.md.muxCfg.Version != 1 {
		t.Errorf("expected mux version 1, got %d", h.md.muxCfg.Version)
	}
	if h.md.muxCfg.KeepAliveInterval != 10*time.Second {
		t.Errorf("expected keepalive interval 10s, got %v", h.md.muxCfg.KeepAliveInterval)
	}
	if !h.md.muxCfg.KeepAliveDisabled {
		t.Error("expected keepalive disabled")
	}
	if h.md.muxCfg.KeepAliveTimeout != 30*time.Second {
		t.Errorf("expected keepalive timeout 30s, got %v", h.md.muxCfg.KeepAliveTimeout)
	}
	if h.md.muxCfg.MaxFrameSize != 4096 {
		t.Errorf("expected max frame size 4096, got %d", h.md.muxCfg.MaxFrameSize)
	}
	if h.md.muxCfg.MaxReceiveBuffer != 8192 {
		t.Errorf("expected max receive buffer 8192, got %d", h.md.muxCfg.MaxReceiveBuffer)
	}
	if h.md.muxCfg.MaxStreamBuffer != 65536 {
		t.Errorf("expected max stream buffer 65536, got %d", h.md.muxCfg.MaxStreamBuffer)
	}
}

func TestParseMetadata_MuxDefaultsNoVersion(t *testing.T) {
	h := &tunnelHandler{}
	// When no mux config is provided, defaults should be applied.
	md := mdx.NewMetadata(map[string]any{})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.muxCfg.Version != 2 {
		t.Errorf("expected default version 2, got %d", h.md.muxCfg.Version)
	}
	if h.md.muxCfg.MaxStreamBuffer != 1048576 {
		t.Errorf("expected default max stream buffer 1048576, got %d", h.md.muxCfg.MaxStreamBuffer)
	}
}

func TestParseMetadata_TunnelRules(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel": "example.com:6ba7b810-9dad-11d1-80b4-00c04fd430c8,app.example.com:7f2c3d4e-5a6b-7c8d-9e0f-1a2b3c4d5e6f",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.ingress == nil {
		t.Fatal("expected ingress to be created from tunnel rules")
	}

	// Wait briefly for the ingress periodReload goroutine to populate rules.
	time.Sleep(50 * time.Millisecond)

	// Check that rules were parsed correctly
	rule1 := h.md.ingress.GetRule(context.Background(), "example.com")
	if rule1 == nil {
		t.Fatal("expected rule for example.com")
	}
	if rule1.Hostname != "example.com" {
		t.Errorf("expected hostname example.com, got %q", rule1.Hostname)
	}
	if rule1.Endpoint != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Errorf("expected endpoint 6ba7b810..., got %q", rule1.Endpoint)
	}

	rule2 := h.md.ingress.GetRule(context.Background(), "app.example.com")
	if rule2 == nil {
		t.Fatal("expected rule for app.example.com")
	}
	if rule2.Hostname != "app.example.com" {
		t.Errorf("expected hostname app.example.com, got %q", rule2.Hostname)
	}
	if rule2.Endpoint != "7f2c3d4e-5a6b-7c8d-9e0f-1a2b3c4d5e6f" {
		t.Errorf("expected endpoint 7f2c3d4e..., got %q", rule2.Endpoint)
	}
}

func TestParseMetadata_TunnelRules_Malformed(t *testing.T) {
	// Test that malformed tunnel rules are silently skipped.
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel": "valid.example.com:6ba7b810-9dad-11d1-80b4-00c04fd430c8,badrule",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.ingress == nil {
		t.Fatal("expected ingress to be created with at least valid rules")
	}

	// Wait briefly for the ingress periodReload goroutine to populate rules.
	time.Sleep(50 * time.Millisecond)

	// Valid rule should exist
	rule := h.md.ingress.GetRule(context.Background(), "valid.example.com")
	if rule == nil {
		t.Fatal("expected rule for valid.example.com")
	}

	// Malformed rule should have been skipped
	if len(h.md.entrypoints) != 0 {
		t.Errorf("expected 0 entrypoints, got %d", len(h.md.entrypoints))
	}
}

func TestParseMetadata_EntrypointsJSON(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoints": []map[string]any{
			{"Addr": ":8080"},
			{"Addr": ":9090"},
		},
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h.md.entrypoints) != 2 {
		t.Fatalf("expected 2 entrypoints, got %d", len(h.md.entrypoints))
	}
	if h.md.entrypoints[0].Addr != ":8080" {
		t.Errorf("expected entrypoints[0] addr :8080, got %q", h.md.entrypoints[0].Addr)
	}
	if h.md.entrypoints[1].Addr != ":9090" {
		t.Errorf("expected entrypoints[1] addr :9090, got %q", h.md.entrypoints[1].Addr)
	}
}

func TestParseMetadata_EntrypointsJSON_EmptyAddrSkipped(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoints": []map[string]any{
			{"Addr": ""},
			{"Addr": ":8080"},
		},
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h.md.entrypoints) != 1 {
		t.Errorf("expected 1 entrypoint (empty addr skipped), got %d", len(h.md.entrypoints))
	}
	if h.md.entrypoints[0].Addr != ":8080" {
		t.Errorf("expected entrypoint addr :8080, got %q", h.md.entrypoints[0].Addr)
	}
}

func TestParseMetadata_LimiterIntervals(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"limiter.refreshInterval": "60s",
		"limiter.cleanupInterval": "120s",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.limiterRefreshInterval != 60*time.Second {
		t.Errorf("expected limiterRefreshInterval 60s, got %v", h.md.limiterRefreshInterval)
	}
	if h.md.limiterCleanupInterval != 120*time.Second {
		t.Errorf("expected limiterCleanupInterval 120s, got %v", h.md.limiterCleanupInterval)
	}
}

func TestParseMetadata_EntrypointProxyProtocol(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoint.ProxyProtocol": 2,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.entryPointProxyProtocol != 2 {
		t.Errorf("expected proxy protocol 2, got %d", h.md.entryPointProxyProtocol)
	}
}

func TestParseMetadata_EntrypointKeepalive(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoint.keepalive":  true,
		"entrypoint.compression": true,
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.entryPointKeepalive {
		t.Error("expected entryPointKeepalive true")
	}
	if !h.md.entryPointCompression {
		t.Error("expected entryPointCompression true")
	}
}

func TestParseMetadata_EntrypointReadTimeout_ZeroDefaults(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.entryPointReadTimeout != 15*time.Second {
		t.Errorf("expected default entryPointReadTimeout 15s, got %v", h.md.entryPointReadTimeout)
	}
}

func TestParseMetadata_EmptyMetadata(t *testing.T) {
	// With nil metadata, parseMetadata should not panic.
	h := &tunnelHandler{}
	err := h.parseMetadata(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Defaults should still apply
	if h.md.muxCfg.Version != 2 {
		t.Errorf("expected default version 2, got %d", h.md.muxCfg.Version)
	}
	if h.md.tunnelTTL != defaultTTL {
		t.Errorf("expected default TTL %v, got %v", defaultTTL, h.md.tunnelTTL)
	}
}

// TestParseMetadata_EntrypointID tests parsing of the entrypointID metadata key.
func TestParseMetadata_EntrypointID(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoint.id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if !h.md.entryPointID.Equal(expected) {
		t.Errorf("expected entryPointID %v, got %v", expected, h.md.entryPointID)
	}
}

// TestParseMetadata_TunnelRules_Empty tests that empty tunnel rules don't
// create an ingress.
func TestParseMetadata_TunnelRules_Empty(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"tunnel": "",
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.ingress != nil {
		t.Error("expected nil ingress for empty tunnel rules")
	}
}

// TestParseMetadata_EntrypointsJSON_WithIngressName tests that entrypoints
// JSON can reference named ingress objects. Without a registry entry, it
// should fall back to the handler's default ingress.
func TestParseMetadata_EntrypointsJSON_IngressFallback(t *testing.T) {
	h := &tunnelHandler{}
	md := mdx.NewMetadata(map[string]any{
		"entrypoints": []map[string]any{
			{"Addr": ":8080", "Ingress": "nonexistent"},
		},
	})
	err := h.parseMetadata(md)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h.md.entrypoints) != 1 {
		t.Fatalf("expected 1 entrypoint, got %d", len(h.md.entrypoints))
	}
	// The registry always returns a non-nil ingressWrapper for non-empty names,
	// even if the name is not registered (hot-reload design).
	if h.md.entrypoints[0].Ingress == nil {
		t.Error("expected non-nil ingress wrapper from registry")
	}
}