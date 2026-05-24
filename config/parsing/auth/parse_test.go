package auth

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

func TestInfo_Nil(t *testing.T) {
	if u := Info(nil); u != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestInfo_EmptyUsername(t *testing.T) {
	u := Info(&config.AuthConfig{Username: ""})
	if u != nil {
		t.Fatal("expected nil for empty username")
	}
}

func TestInfo_UsernameOnly(t *testing.T) {
	u := Info(&config.AuthConfig{Username: "user"})
	if u == nil {
		t.Fatal("expected non-nil userinfo")
	}
	if u.Username() != "user" {
		t.Fatalf("username = %q, want %q", u.Username(), "user")
	}
	if _, hasPassword := u.Password(); hasPassword {
		t.Fatal("expected no password")
	}
}

func TestInfo_UsernameAndPassword(t *testing.T) {
	u := Info(&config.AuthConfig{Username: "user", Password: "pass"})
	if u == nil {
		t.Fatal("expected non-nil userinfo")
	}
	if u.Username() != "user" {
		t.Fatalf("username = %q, want %q", u.Username(), "user")
	}
	if p, ok := u.Password(); !ok || p != "pass" {
		t.Fatalf("password = %q, want %q", p, "pass")
	}
}

func TestInfo_WithFile(t *testing.T) {
	// File that doesn't exist - should fall back to username
	u := Info(&config.AuthConfig{
		Username: "fallback",
		Password: "pass",
		File:     "/nonexistent/auth_file",
	})
	if u == nil {
		t.Fatal("expected non-nil userinfo (fallback)")
	}
	if u.Username() != "fallback" {
		t.Fatalf("username = %q, want %q", u.Username(), "fallback")
	}
}

func TestParseAutherFromAuth_Nil(t *testing.T) {
	a := ParseAutherFromAuth(nil)
	if a != nil {
		t.Fatal("expected nil for nil auth config")
	}
}

func TestParseAutherFromAuth_EmptyUsername(t *testing.T) {
	a := ParseAutherFromAuth(&config.AuthConfig{Username: ""})
	if a != nil {
		t.Fatal("expected nil for empty username")
	}
}

func TestParseAutherFromAuth_Valid(t *testing.T) {
	a := ParseAutherFromAuth(&config.AuthConfig{
		Username: "user",
		Password: "pass",
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestParseAuther_Nil(t *testing.T) {
	a := ParseAuther(nil)
	if a != nil {
		t.Fatal("expected nil for nil config")
	}
}

func TestParseAuther_WithUsers(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "test-auth",
		Auths: []*config.AuthConfig{
			{Username: "u1", Password: "p1"},
			{Username: "u2", Password: "p2"},
			{Username: "", Password: "nope"}, // skipped
		},
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestParseAuther_WithEmptyAuths(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name:  "empty-auth",
		Auths: []*config.AuthConfig{},
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestParseAuther_PluginHTTP(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "http-plugin",
		Plugin: &config.PluginConfig{
			Type: "http",
			Addr: "127.0.0.1:9000",
		},
	})
	if a == nil {
		t.Fatal("expected non-nil plugin authenticator")
	}
}

func TestParseAuther_PluginGRPC(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "grpc-plugin",
		Plugin: &config.PluginConfig{
			Type:  "grpc",
			Addr:  "127.0.0.1:9001",
			Token: "secret",
			TLS: &config.TLSConfig{
				Secure:     true,
				ServerName: "auth.local",
			},
		},
	})
	if a == nil {
		t.Fatal("expected non-nil plugin authenticator")
	}
}

func TestParseAuther_PluginDefaultType(t *testing.T) {
	// Default plugin type should be treated as gRPC
	a := ParseAuther(&config.AutherConfig{
		Name: "default-plugin",
		Plugin: &config.PluginConfig{
			Addr: "127.0.0.1:9002",
		},
	})
	if a == nil {
		t.Fatal("expected non-nil plugin authenticator")
	}
}

func TestInfo_ParseFile(t *testing.T) {
	// parseInfo with empty reader should return nil
	u := Info(&config.AuthConfig{
		File: "/nonexistent/file",
	})
	if u != nil {
		t.Fatal("expected nil for nonexistent file (should not crash)")
	}
}

func TestList_ReturnsEntries(t *testing.T) {
	// The registry returns a lazy wrapper for any non-empty name.
	got := List("test-auther", "test-auther-2")
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

func TestParseAuther_HTTPLoader(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "http-loader-auth",
		HTTP: &config.HTTPLoader{
			URL: "http://localhost:8080/auth",
		},
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestParseAuther_FileLoader(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "file-loader-auth",
		File: &config.FileLoader{
			Path: "/tmp/auth.txt",
		},
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestParseAuther_RedisLoader(t *testing.T) {
	a := ParseAuther(&config.AutherConfig{
		Name: "redis-loader-auth",
		Redis: &config.RedisLoader{
			Addr: "127.0.0.1:6379",
		},
	})
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestInfo_Integration(t *testing.T) {
	// Verify Info returns *url.Userinfo whose String() matches the standard library.
	u := Info(&config.AuthConfig{Username: "alice", Password: "secret"})
	if u == nil {
		t.Fatal("expected non-nil")
	}
	want := "alice:secret"
	if u.String() != want {
		t.Fatalf("String() = %q, want %q", u.String(), want)
	}
}
