package admission

import (
	"io"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
)

func TestMain(m *testing.M) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	m.Run()
}

func TestParseAdmission_Nil(t *testing.T) {
	adm := ParseAdmission(nil)
	if adm != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseAdmission_PluginHTTP(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "http-adm",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_PluginGRPC(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "grpc-adm",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "admission.local",
			},
		},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_PluginDefaultType(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "default-adm",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_WithMatchers(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name:     "matcher-adm",
		Matchers: []string{"192.168.0.0/16", "10.0.0.1"},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_Whitelist(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name:      "whitelist-adm",
		Whitelist: true,
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_Reverse(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name:    "reverse-adm",
		Reverse: true,
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_FileLoader(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "file-adm",
		File: &config.FileLoader{Path: "/tmp/admission.txt"},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_HTTPLoader(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "http-adm",
		HTTP: &config.HTTPLoader{URL: "http://localhost:8080/list"},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestParseAdmission_RedisLoader(t *testing.T) {
	adm := ParseAdmission(&config.AdmissionConfig{
		Name: "redis-adm",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
			Key:  "admission-set",
		},
	})
	if adm == nil {
		t.Fatal("expected non-nil admission")
	}
}

func TestList_ReturnsEntries(t *testing.T) {
	// The registry returns a lazy wrapper for any non-empty name.
	got := List("test-admission", "test-admission-2")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestList_EmptyNameReturnsNothing(t *testing.T) {
	// Empty names are filtered by the registry Get.
	got := List("")
	if len(got) != 0 {
		t.Fatal("expected empty list for empty name")
	}
}
