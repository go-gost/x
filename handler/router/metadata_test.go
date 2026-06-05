package router

import (
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
)

func TestParseMetadata_Empty(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.readTimeout != 0 {
		t.Errorf("readTimeout = %v, want 0", h.md.readTimeout)
	}
	if h.md.bufferSize != defaultBufferSize {
		t.Errorf("bufferSize = %d, want %d", h.md.bufferSize, defaultBufferSize)
	}
	if h.md.entryPoint != "" {
		t.Errorf("entryPoint = %q, want empty", h.md.entryPoint)
	}
	if h.md.ingress != nil {
		t.Errorf("ingress = %v, want nil", h.md.ingress)
	}
	if h.md.sd != nil {
		t.Errorf("sd = %v, want nil", h.md.sd)
	}
	if h.md.sdCacheExpiration != defaultCacheExpiration {
		t.Errorf("sdCacheExpiration = %v, want %v", h.md.sdCacheExpiration, defaultCacheExpiration)
	}
	if h.md.sdRenewInterval != defaultTTL {
		t.Errorf("sdRenewInterval = %v, want %v", h.md.sdRenewInterval, defaultTTL)
	}
	if h.md.router != nil {
		t.Errorf("router = %v, want nil", h.md.router)
	}
	if h.md.routerCacheEnabled {
		t.Error("routerCacheEnabled = true, want false")
	}
	if h.md.observerPeriod != 5*time.Second {
		t.Errorf("observerPeriod = %v, want 5s", h.md.observerPeriod)
	}
	if h.md.observerResetTraffic {
		t.Error("observerResetTraffic = true, want false")
	}
}

func TestParseMetadata_ReadTimeout(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"readTimeout": "10s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.readTimeout != 10*time.Second {
		t.Errorf("readTimeout = %v, want 10s", h.md.readTimeout)
	}
}

func TestParseMetadata_BufferSize(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"router.bufferSize": 8192,
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.bufferSize != 8192 {
		t.Errorf("bufferSize = %d, want 8192", h.md.bufferSize)
	}
}

func TestParseMetadata_BufferSize_Zero(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"router.bufferSize": 0,
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.bufferSize != defaultBufferSize {
		t.Errorf("bufferSize = %d, want %d", h.md.bufferSize, defaultBufferSize)
	}
}

func TestParseMetadata_EntryPoint(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"entrypoint": ":8080",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.entryPoint != ":8080" {
		t.Errorf("entryPoint = %q, want :8080", h.md.entryPoint)
	}
}

func TestParseMetadata_SDCacheExpiration(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"sd.cache.expiration": "30s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.sdCacheExpiration != 30*time.Second {
		t.Errorf("sdCacheExpiration = %v, want 30s", h.md.sdCacheExpiration)
	}
}

func TestParseMetadata_SDRenewInterval(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"sd.renewInterval": "30s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.sdRenewInterval != 30*time.Second {
		t.Errorf("sdRenewInterval = %v, want 30s", h.md.sdRenewInterval)
	}
}

func TestParseMetadata_SDRenewInterval_TooSmall(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"sd.renewInterval": "100ms",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.sdRenewInterval != defaultTTL {
		t.Errorf("sdRenewInterval = %v, want %v", h.md.sdRenewInterval, defaultTTL)
	}
}

func TestParseMetadata_RouterCache(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"router.cache":            true,
		"router.cache.expiration": "30s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.routerCacheEnabled {
		t.Error("routerCacheEnabled = false, want true")
	}
	if h.md.routerCacheExpiration != 30*time.Second {
		t.Errorf("routerCacheExpiration = %v, want 30s", h.md.routerCacheExpiration)
	}
}

func TestParseMetadata_RouterCache_DefaultExpiration(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"router.cache": true,
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.routerCacheExpiration != defaultCacheExpiration {
		t.Errorf("routerCacheExpiration = %v, want %v", h.md.routerCacheExpiration, defaultCacheExpiration)
	}
}

func TestParseMetadata_ObserverPeriod(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"observePeriod": "10s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.observerPeriod != 10*time.Second {
		t.Errorf("observerPeriod = %v, want 10s", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverPeriod_TooSmall(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"observePeriod": "100ms",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.observerPeriod != time.Second {
		t.Errorf("observerPeriod = %v, want 1s", h.md.observerPeriod)
	}
}

func TestParseMetadata_ObserverResetTraffic(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"observer.resetTraffic": true,
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.md.observerResetTraffic {
		t.Error("observerResetTraffic = false, want true")
	}
}

func TestParseMetadata_LimiterRefresh(t *testing.T) {
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"limiter.refreshInterval": "30s",
		"limiter.cleanupInterval": "60s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.limiterRefreshInterval != 30*time.Second {
		t.Errorf("limiterRefreshInterval = %v, want 30s", h.md.limiterRefreshInterval)
	}
	if h.md.limiterCleanupInterval != 60*time.Second {
		t.Errorf("limiterCleanupInterval = %v, want 60s", h.md.limiterCleanupInterval)
	}
}

func TestParseMetadata_FallbackKeys(t *testing.T) {
	// Verify fallback key patterns for observerPeriod
	h := &routerHandler{
		options: handler.Options{
			Logger: logger.Default(),
		},
	}
	if err := h.parseMetadata(testMD(map[string]any{
		"observer.period": "3s",
	})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.md.observerPeriod != 3*time.Second {
		t.Errorf("observerPeriod = %v, want 3s (from observer.period)", h.md.observerPeriod)
	}
}