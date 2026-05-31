package tls

import (
	"crypto/tls"
	"testing"
)

func TestRejectUnknownSNIConfig_Disabled(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, false, nil)
	if cfg.GetConfigForClient != nil {
		t.Error("GetConfigForClient should be nil when rejectUnknownSNI is false")
	}
}

func TestRejectUnknownSNIConfig_EmptyServerName(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, nil)
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	_, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error for empty ServerName")
	}
}

func TestRejectUnknownSNIConfig_NamedAllowed(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, nil)
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	result, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != cfg {
		t.Error("expected the original config to be returned")
	}
}

func TestRejectUnknownSNIConfig_WithAllowList_Match(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, []string{"example.com", "test.org"})
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	result, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != cfg {
		t.Error("expected the original config to be returned")
	}
}

func TestRejectUnknownSNIConfig_WithAllowList_NoMatch(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, []string{"example.com", "test.org"})
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	_, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "evil.com"})
	if err == nil {
		t.Error("expected error for non-matching ServerName")
	}
}

func TestRejectUnknownSNIConfig_WithAllowList_CaseInsensitive(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, []string{"Example.COM"})
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	result, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != cfg {
		t.Error("expected the original config to be returned")
	}
}

func TestRejectUnknownSNIConfig_WithAllowList_EmptySNI(t *testing.T) {
	cfg := &tls.Config{}
	RejectUnknownSNIConfig(cfg, true, []string{"example.com"})
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient should be set")
	}

	_, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err == nil {
		t.Error("expected error for empty ServerName when allowList is set")
	}
}