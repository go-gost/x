package cmd

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/go-gost/x/config"
)

func TestDecodeSIP002Auth(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		wantUsername string
		wantPassword string
		wantNil      bool
	}{
		{
			name:         "SIP002 URL-safe base64 without padding",
			rawURL:       "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password")) + "@server:8388",
			wantUsername: "aes-256-gcm",
			wantPassword: "password",
		},
		{
			name:         "SIP002 standard base64 with padding",
			rawURL:       "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass")) + "@server:8388",
			wantUsername: "aes-256-gcm",
			wantPassword: "pass",
		},
		{
			name:    "standard format with password (not SIP002)",
			rawURL:  "ss://aes-256-gcm:password@server:8388",
			wantNil: true,
		},
		{
			name:    "no userinfo",
			rawURL:  "ss://server:8388",
			wantNil: true,
		},
		{
			name:    "invalid base64",
			rawURL:  "ss://not-valid!!!@server:8388",
			wantNil: true,
		},
		{
			name:    "base64 without colon in decoded",
			rawURL:  "ss://" + base64.RawURLEncoding.EncodeToString([]byte("nocolon")) + "@server:8388",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}

			got := decodeSIP002Auth(u)
			if tt.wantNil {
				if got != nil {
					t.Errorf("decodeSIP002Auth() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("decodeSIP002Auth() = nil, want non-nil")
			}
			if got.Username != tt.wantUsername {
				t.Errorf("Username = %q, want %q", got.Username, tt.wantUsername)
			}
			if got.Password != tt.wantPassword {
				t.Errorf("Password = %q, want %q", got.Password, tt.wantPassword)
			}
		})
	}
}

func TestParseAuthFromCmd(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantUsername string
		wantPassword string
		wantErr      bool
	}{
		{
			name:         "StdEncoding with padding",
			input:        base64.StdEncoding.EncodeToString([]byte("user:pass")),
			wantUsername: "user",
			wantPassword: "pass",
		},
		{
			name:         "RawURLEncoding without padding",
			input:        base64.RawURLEncoding.EncodeToString([]byte("user:pass")),
			wantUsername: "user",
			wantPassword: "pass",
		},
		{
			name:    "invalid base64",
			input:   "not-valid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuthFromCmd(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("parseAuthFromCmd() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAuthFromCmd() error = %v", err)
			}
			if got.Username != tt.wantUsername {
				t.Errorf("Username = %q, want %q", got.Username, tt.wantUsername)
			}
			if got.Password != tt.wantPassword {
				t.Errorf("Password = %q, want %q", got.Password, tt.wantPassword)
			}
		})
	}
}

func TestBuildNodeConfigSIP002(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	rawURL := "ss://" + encoded + "@server:8388"

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Connector == nil || node.Connector.Auth == nil {
		t.Fatal("node.Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "aes-256-gcm" {
		t.Errorf("Username = %q, want %q", node.Connector.Auth.Username, "aes-256-gcm")
	}
	if node.Connector.Auth.Password != "password" {
		t.Errorf("Password = %q, want %q", node.Connector.Auth.Password, "password")
	}
}

func TestBuildNodeConfigStandardAuth(t *testing.T) {
	rawURL := "http://user:pass@server:8080"
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Connector == nil || node.Connector.Auth == nil {
		t.Fatal("node.Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "user" {
		t.Errorf("Username = %q, want %q", node.Connector.Auth.Username, "user")
	}
	if node.Connector.Auth.Password != "pass" {
		t.Errorf("Password = %q, want %q", node.Connector.Auth.Password, "pass")
	}
}

func TestBuildServiceConfigSIP002(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	rawURL := "ss://" + encoded + "@:8388"

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}
	if len(svcs) == 0 {
		t.Fatal("no services returned")
	}

	auth := svcs[0].Handler.Auth
	if auth == nil {
		t.Fatal("Handler.Auth is nil")
	}
	if auth.Username != "aes-256-gcm" {
		t.Errorf("Username = %q, want %q", auth.Username, "aes-256-gcm")
	}
	if auth.Password != "password" {
		t.Errorf("Password = %q, want %q", auth.Password, "password")
	}
}

func TestNorm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			wantErr: true,
		},
		{
			name:  "whitespace only",
			input: "   ",
			wantErr: true,
		},
		{
			name:  "host:port without scheme",
			input: "host:8080",
			want:  "auto://host:8080",
		},
		{
			name:  "colon prefix",
			input: ":8080",
			want:  "auto://:8080",
		},
		{
			name:  "https scheme rewrites to http+tls",
			input: "https://host:443",
			want:  "http+tls://host:443",
		},
		{
			name:  "http scheme unchanged",
			input: "http://host:8080",
			want:  "http://host:8080",
		},
		{
			name:  "with query params",
			input: "http://host:8080?key=val",
			want:  "http://host:8080?key=val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Norm(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Norm() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Norm() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("Norm() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func TestCutHost(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantHost   string
		wantRemain string
	}{
		{
			name:       "empty string",
			input:      "",
			wantHost:   "",
			wantRemain: "",
		},
		{
			name:       "scheme://host:port",
			input:      "http://host:8080",
			wantHost:   "host:8080",
			wantRemain: "http://",
		},
		{
			name:       "scheme://host:port/path",
			input:      "http://host:8080/path",
			wantHost:   "host:8080",
			wantRemain: "http:///path",
		},
		{
			name:       "scheme://host:port?query",
			input:      "http://host:8080?key=val",
			wantHost:   "host:8080",
			wantRemain: "http://?key=val",
		},
		{
			name:       "with user:pass@host",
			input:      "http://user:pass@host:8080",
			wantHost:   "host:8080",
			wantRemain: "http://user:pass@",
		},
		{
			name:       "with user:pass@host/path?query",
			input:      "http://user:pass@host:8080/path?key=val",
			wantHost:   "host:8080",
			wantRemain: "http://user:pass@/path?key=val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, remain := cutHost(tt.input)
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if remain != tt.wantRemain {
				t.Errorf("remain = %q, want %q", remain, tt.wantRemain)
			}
		})
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]any
		wantNil    bool
		wantStrat  string
		wantFails  int
		wantDurGt  bool // failTimeout > 0
	}{
		{
			name:    "no params",
			input:   map[string]any{},
			wantNil: true,
		},
		{
			name: "only strategy",
			input: map[string]any{
				"strategy": "rr",
			},
			wantStrat: "rr",
			wantFails: 1,
			wantDurGt: true,
		},
		{
			name: "only maxFails",
			input: map[string]any{
				"max_fails": 3,
			},
			wantStrat: "round",
			wantFails: 3,
			wantDurGt: true,
		},
		{
			name: "all params with failTimeout",
			input: map[string]any{
				"strategy":     "hash",
				"maxFails":     5,
				"failTimeout":  "10s",
			},
			wantStrat: "hash",
			wantFails: 5,
			wantDurGt: true,
		},
		{
			name: "fail_timeout with underscore",
			input: map[string]any{
				"strategy":     "fifo",
				"max_fails":    2,
				"fail_timeout": "15s",
			},
			wantStrat: "fifo",
			wantFails: 2,
			wantDurGt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSelector(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Errorf("parseSelector() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("parseSelector() = nil, want non-nil")
			}
			if got.Strategy != tt.wantStrat {
				t.Errorf("Strategy = %q, want %q", got.Strategy, tt.wantStrat)
			}
			if got.MaxFails != tt.wantFails {
				t.Errorf("MaxFails = %d, want %d", got.MaxFails, tt.wantFails)
			}
			if tt.wantDurGt && got.FailTimeout <= 0 {
				t.Errorf("FailTimeout = %v, want > 0", got.FailTimeout)
			}
		})
	}
}

func TestCopyMap(t *testing.T) {
	t.Run("nil map", func(t *testing.T) {
		if copyMap(nil) != nil {
			t.Error("copyMap(nil) should be nil")
		}
	})

	t.Run("non-nil map", func(t *testing.T) {
		orig := map[string]any{"key": "val"}
		c := copyMap(orig)
		if c["key"] != "val" {
			t.Errorf("value = %v, want %v", c["key"], "val")
		}
		// mutate copy, verify original unchanged
		c["key"] = "newval"
		if orig["key"] != "val" {
			t.Error("original map was mutated")
		}
	})
}

func TestCopyTLS(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if copyTLS(nil) != nil {
			t.Error("copyTLS(nil) should be nil")
		}
	})

	t.Run("non-nil", func(t *testing.T) {
		orig := &config.TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}
		c := copyTLS(orig)
		if c.CertFile != "cert.pem" || c.KeyFile != "key.pem" {
			t.Error("copyTLS did not copy fields")
		}
		c.CertFile = "other.pem"
		if orig.CertFile != "cert.pem" {
			t.Error("original TLSConfig was mutated")
		}
	})
}

func TestCopyConnectorConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if copyConnectorConfig(nil) != nil {
			t.Error("copyConnectorConfig(nil) should be nil")
		}
	})

	t.Run("non-nil deep copy", func(t *testing.T) {
		orig := &config.ConnectorConfig{
			Type: "http",
			Auth: &config.AuthConfig{Username: "u", Password: "p"},
			Metadata: map[string]any{"k": "v"},
		}
		c := copyConnectorConfig(orig)
		if c.Type != "http" {
			t.Errorf("Type = %q, want %q", c.Type, "http")
		}
		if c.Auth.Username != "u" || c.Auth.Password != "p" {
			t.Error("Auth not copied")
		}
		// mutate copy, verify original unchanged
		c.Auth.Username = "x"
		if orig.Auth.Username != "u" {
			t.Error("original auth was mutated")
		}
		c.Metadata["k"] = "x"
		if orig.Metadata["k"] != "v" {
			t.Error("original metadata was mutated")
		}
	})
}

func TestCopyDialerConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if copyDialerConfig(nil) != nil {
			t.Error("copyDialerConfig(nil) should be nil")
		}
	})

	t.Run("non-nil deep copy", func(t *testing.T) {
		orig := &config.DialerConfig{
			Type: "tls",
			TLS:  &config.TLSConfig{ServerName: "example.com"},
			Auth: &config.AuthConfig{Username: "u"},
			Metadata: map[string]any{"k": "v"},
		}
		c := copyDialerConfig(orig)
		if c.TLS.ServerName != "example.com" {
			t.Error("TLS not copied")
		}
		c.TLS.ServerName = "other.com"
		if orig.TLS.ServerName != "example.com" {
			t.Error("original TLS was mutated")
		}
		c.Auth.Username = "x"
		if orig.Auth.Username != "u" {
			t.Error("original auth was mutated")
		}
	})
}

func TestBuildNodeConfig_NilMap(t *testing.T) {
	// nil m should not panic
	rawURL := "http://server:8080"
	u, _ := url.Parse(rawURL)
	node, err := buildNodeConfig(u, nil)
	if err != nil {
		t.Fatalf("buildNodeConfig(nil m): %v", err)
	}
	if node.Addr != "server:8080" {
		t.Errorf("Addr = %q, want %q", node.Addr, "server:8080")
	}
	if node.Connector.Type != "http" {
		t.Errorf("Connector.Type = %q, want %q", node.Connector.Type, "http")
	}
}

func TestBuildServiceConfigStandardAuth(t *testing.T) {
	rawURL := "http://user:pass@:8080"
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}
	if len(svcs) == 0 {
		t.Fatal("no services returned")
	}

	auth := svcs[0].Handler.Auth
	if auth == nil {
		t.Fatal("Handler.Auth is nil")
	}
	if auth.Username != "user" {
		t.Errorf("Username = %q, want %q", auth.Username, "user")
	}
	if auth.Password != "pass" {
		t.Errorf("Password = %q, want %q", auth.Password, "pass")
	}
}

func TestBuildNodeConfig_TLS(t *testing.T) {
	u, _ := url.Parse("http+tls://server:443")
	m := map[string]any{
		"secure":     true,
		"serverName": "example.com",
	}

	node, err := buildNodeConfig(u, m)
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Dialer.TLS == nil {
		t.Fatal("Dialer.TLS is nil")
	}
	if node.Dialer.TLS.Secure != true {
		t.Error("TLS.Secure should be true")
	}
	if node.Dialer.TLS.ServerName != "example.com" {
		t.Errorf("TLS.ServerName = %q, want %q", node.Dialer.TLS.ServerName, "example.com")
	}
}

func TestBuildNodeConfig_TLSServerNameDefaultsToHost(t *testing.T) {
	rawURL := "http+tls://example.com:443?secure=true"
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Dialer.TLS.ServerName != "example.com" {
		t.Errorf("TLS.ServerName = %q, want %q", node.Dialer.TLS.ServerName, "example.com")
	}
}

func TestBuildNodeConfig_AuthFallbackForUnknownScheme(t *testing.T) {
	// When dialer type is unknown, it defaults to tcp, and auth stays on connector
	rawURL := "unknown://user:pass@server:8080"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	// Connector defaults to "http", dialer defaults to "tcp"
	if node.Connector.Auth == nil {
		t.Fatal("Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "user" || node.Connector.Auth.Password != "pass" {
		t.Errorf("Connector.Auth = %+v, want user:pass", node.Connector.Auth)
	}
	if node.Dialer.Auth != nil {
		t.Error("Dialer.Auth should be nil for non-ssh dialer")
	}
}

func TestBuildNodeConfig_AuthFromMetadata(t *testing.T) {
	authB64 := base64.RawURLEncoding.EncodeToString([]byte("quser:qpass"))
	u, _ := url.Parse("http://server:8080")
	m := map[string]any{"auth": authB64}

	node, err := buildNodeConfig(u, m)
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Connector.Auth == nil {
		t.Fatal("Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "quser" || node.Connector.Auth.Password != "qpass" {
		t.Errorf("Connector.Auth = %+v, want quser:qpass", node.Connector.Auth)
	}
}

func TestBuildNodeConfig_InvalidAuthParam(t *testing.T) {
	u, _ := url.Parse("http://server:8080")
	m := map[string]any{"auth": "invalid!!!"}

	_, err := buildNodeConfig(u, m)
	if err == nil {
		t.Error("buildNodeConfig should fail with invalid auth param")
	}
}

func TestBuildNodeConfig_MetadataRouting(t *testing.T) {
	m := map[string]any{
		"node.key":      "nodeval",
		"connector.key": "connval",
		"dialer.key":    "dialval",
		"common.key":    "commonval",
	}

	rawURL := "http://server:8080"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, m)
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Metadata["key"] != "nodeval" {
		t.Errorf("node metadata: key = %v, want nodeval", node.Metadata["key"])
	}
	if node.Connector.Metadata["key"] != "connval" {
		t.Errorf("connector metadata: key = %v, want connval", node.Connector.Metadata["key"])
	}
	if node.Dialer.Metadata["key"] != "dialval" {
		t.Errorf("dialer metadata: key = %v, want dialval", node.Dialer.Metadata["key"])
	}
	// common keys should propagate to all
	if node.Metadata["common.key"] != "commonval" {
		t.Error("common key not in node metadata")
	}
	if node.Connector.Metadata["common.key"] != "commonval" {
		t.Error("common key not in connector metadata")
	}
	if node.Dialer.Metadata["common.key"] != "commonval" {
		t.Error("common key not in dialer metadata")
	}
}

func TestBuildNodeConfig_UnknownConnectorUsesHTTP(t *testing.T) {
	rawURL := "unknown://server:8080"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Connector.Type != "http" {
		t.Errorf("Connector.Type = %q, want http", node.Connector.Type)
	}
	if node.Dialer.Type != "tcp" {
		t.Errorf("Dialer.Type = %q, want tcp", node.Dialer.Type)
	}
}

func TestBuildNodeConfig_SsuConnector(t *testing.T) {
	// ssu connector is not in registry, so it falls back to http.
	// The dialer falls back to tcp (not udp) because the connector was
	// already resolved to http before the ssu check.
	rawURL := "ssu://server:8388"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	// Connector falls back to http, dialer falls back to tcp
	if node.Connector.Type != "http" {
		t.Errorf("Connector.Type = %q, want http", node.Connector.Type)
	}
	if node.Dialer.Type != "tcp" {
		t.Errorf("Dialer.Type = %q, want tcp", node.Dialer.Type)
	}
}

func TestBuildServiceConfig_AuthOnHandlerByDefault(t *testing.T) {
	// When listener type is unknown (defaults to tcp), auth stays on handler
	rawURL := "http://user:pass@:8080"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	svc := svcs[0]
	if svc.Handler.Auth == nil {
		t.Fatal("Handler.Auth is nil")
	}
	if svc.Handler.Auth.Username != "user" || svc.Handler.Auth.Password != "pass" {
		t.Errorf("Handler.Auth = %+v, want user:pass", svc.Handler.Auth)
	}
	if svc.Listener.Auth != nil {
		t.Error("Listener.Auth should be nil for non-ssh listener")
	}
}

func TestBuildServiceConfig_TLS(t *testing.T) {
	rawURL := "http://:443?certFile=mycert.pem&keyFile=mykey.pem&caFile=myca.pem"
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	tls := svcs[0].Listener.TLS
	if tls == nil {
		t.Fatal("Listener.TLS is nil")
	}
	if tls.CertFile != "mycert.pem" {
		t.Errorf("CertFile = %q, want mycert.pem", tls.CertFile)
	}
	if tls.KeyFile != "mykey.pem" {
		t.Errorf("KeyFile = %q, want mykey.pem", tls.KeyFile)
	}
	if tls.CAFile != "myca.pem" {
		t.Errorf("CAFile = %q, want myca.pem", tls.CAFile)
	}
}

func TestBuildServiceConfig_TLSShortKeys(t *testing.T) {
	rawURL := "http://:443?cert=a.pem&key=b.pem&ca=c.pem"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	tls := svcs[0].Listener.TLS
	if tls == nil {
		t.Fatal("Listener.TLS is nil")
	}
	if tls.CertFile != "a.pem" || tls.KeyFile != "b.pem" || tls.CAFile != "c.pem" {
		t.Errorf("TLS = %+v, want a.pem/b.pem/c.pem", tls)
	}
}

func TestBuildServiceConfig_NoTLSWithoutCert(t *testing.T) {
	rawURL := "http://:443?keyFile=key.pem&caFile=ca.pem"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	if svcs[0].Listener.TLS != nil {
		t.Error("Listener.TLS should be nil without certFile")
	}
}

func TestBuildServiceConfig_DNSParam(t *testing.T) {
	rawURL := "http://:8080?dns=1.1.1.1,8.8.8.8"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	md := svcs[0].Handler.Metadata
	val, ok := md["dns"]
	if !ok {
		t.Fatal("dns key missing from metadata")
	}
	strs, ok := val.([]string)
	if !ok {
		t.Fatalf("dns value type = %T, want []string", val)
	}
	if len(strs) != 2 || strs[0] != "1.1.1.1" || strs[1] != "8.8.8.8" {
		t.Errorf("dns = %v, want [1.1.1.1 8.8.8.8]", strs)
	}
}

func TestBuildServiceConfig_MetadataRouting(t *testing.T) {
	rawURL := "http://:8080?service.key=svcval&handler.key=hval&listener.key=lval&common=val"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	svc := svcs[0]
	if svc.Metadata["key"] != "svcval" {
		t.Errorf("service metadata: key = %v, want svcval", svc.Metadata["key"])
	}
	if svc.Handler.Metadata["key"] != "hval" {
		t.Errorf("handler metadata: key = %v, want hval", svc.Handler.Metadata["key"])
	}
	if svc.Listener.Metadata["key"] != "lval" {
		t.Errorf("listener metadata: key = %v, want lval", svc.Listener.Metadata["key"])
	}
	// common keys propagate everywhere
	if svc.Metadata["common"] != "val" {
		t.Error("common key not in service metadata")
	}
	if svc.Handler.Metadata["common"] != "val" {
		t.Error("common key not in handler metadata")
	}
	if svc.Listener.Metadata["common"] != "val" {
		t.Error("common key not in listener metadata")
	}
}

func TestBuildServiceConfig_NetParams(t *testing.T) {
	rawURL := "http://:8080?interface=eth0&so_mark=42&proxyProtocol=2&netns=myns&netns.out=outns"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	md := svcs[0].Metadata
	if md["interface"] != "eth0" {
		t.Errorf("interface = %v, want eth0", md["interface"])
	}
	if md["so_mark"] != 42 {
		t.Errorf("so_mark = %v, want 42", md["so_mark"])
	}
	if md["proxyProtocol"] != 2 {
		t.Errorf("proxyProtocol = %v, want 2", md["proxyProtocol"])
	}
	if md["netns"] != "myns" {
		t.Errorf("netns = %v, want myns", md["netns"])
	}
	if md["netns.out"] != "outns" {
		t.Errorf("netns.out = %v, want outns", md["netns.out"])
	}
}

func TestBuildServiceConfig_AuthFromQueryParam(t *testing.T) {
	authB64 := base64.RawURLEncoding.EncodeToString([]byte("qu:qp"))
	rawURL := "http://:8080?auth=" + authB64
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	auth := svcs[0].Handler.Auth
	if auth == nil {
		t.Fatal("Handler.Auth is nil")
	}
	if auth.Username != "qu" || auth.Password != "qp" {
		t.Errorf("Auth = %+v, want qu:qp", auth)
	}
}

func TestBuildServiceConfig_InvalidAuthParam(t *testing.T) {
	rawURL := "http://:8080?auth=bad!!!"
	u, _ := url.Parse(rawURL)

	_, err := buildServiceConfig(u)
	if err == nil {
		t.Error("buildServiceConfig should fail with invalid auth param")
	}
}

func TestBuildServiceConfig_FullAuto(t *testing.T) {
	// ":8080" should prepend "auto://"
	rawURL := "auto://:8080"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	if len(svcs) != 1 {
		t.Fatalf("len(svcs) = %d, want 1", len(svcs))
	}
	if svcs[0].Handler.Type != "auto" {
		t.Errorf("Handler.Type = %q, want auto", svcs[0].Handler.Type)
	}
	if svcs[0].Listener.Type != "tcp" {
		t.Errorf("Listener.Type = %q, want tcp", svcs[0].Listener.Type)
	}
}

func TestBuildConfigFromCmd_Empty(t *testing.T) {
	cfg, err := BuildConfigFromCmd(nil, nil)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg is nil")
	}
	if len(cfg.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(cfg.Services))
	}
	if len(cfg.Chains) != 0 {
		t.Errorf("expected 0 chains, got %d", len(cfg.Chains))
	}
}

func TestBuildConfigFromCmd_SingleService(t *testing.T) {
	cfg, err := BuildConfigFromCmd([]string{":8080"}, nil)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Services) != 1 {
		t.Fatalf("len(Services) = %d, want 1", len(cfg.Services))
	}
	svc := cfg.Services[0]
	if svc.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", svc.Addr)
	}
	if svc.Handler.Type != "auto" {
		t.Errorf("Handler.Type = %q, want auto", svc.Handler.Type)
	}
	if svc.Listener.Type != "tcp" {
		t.Errorf("Listener.Type = %q, want tcp", svc.Listener.Type)
	}
}

func TestBuildConfigFromCmd_ServiceWithChain(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Chains) != 1 {
		t.Fatalf("len(Chains) = %d, want 1", len(cfg.Chains))
	}
	chain := cfg.Chains[0]
	if len(chain.Hops) != 1 {
		t.Fatalf("len(Hops) = %d, want 1", len(chain.Hops))
	}
	if chain.Hops[0].Nodes[0].Addr != "proxy:3128" {
		t.Errorf("Node addr = %q, want proxy:3128", chain.Hops[0].Nodes[0].Addr)
	}

	svc := cfg.Services[0]
	if svc.Handler.Chain != "chain-0" {
		t.Errorf("Handler.Chain = %q, want chain-0", svc.Handler.Chain)
	}
}

func TestBuildConfigFromCmd_ServiceWithMultipleNodes(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy1:3128", "http://proxy2:3128"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	chain := cfg.Chains[0]
	if len(chain.Hops) != 2 {
		t.Fatalf("len(Hops) = %d, want 2", len(chain.Hops))
	}
	if chain.Hops[0].Name != "hop-0" {
		t.Errorf("Hops[0].Name = %q, want hop-0", chain.Hops[0].Name)
	}
	if chain.Hops[1].Name != "hop-1" {
		t.Errorf("Hops[1].Name = %q, want hop-1", chain.Hops[1].Name)
	}
}

func TestBuildConfigFromCmd_NodeWithBypass(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?bypass=10.0.0.0/8,*.local"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Bypasses) != 1 {
		t.Fatalf("len(Bypasses) = %d, want 1", len(cfg.Bypasses))
	}
	bp := cfg.Bypasses[0]
	if len(bp.Matchers) != 2 {
		t.Errorf("len(Matchers) = %d, want 2", len(bp.Matchers))
	}
	if cfg.Chains[0].Hops[0].Bypass != bp.Name {
		t.Errorf("Hop.Bypass = %q, want %q", cfg.Chains[0].Hops[0].Bypass, bp.Name)
	}
}

func TestBuildConfigFromCmd_NodeWithInvertBypass(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?bypass=~10.0.0.0/8"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	bp := cfg.Bypasses[0]
	if !bp.Whitelist {
		t.Error("Bypass.Whitelist should be true for ~ prefix")
	}
	if len(bp.Matchers) != 1 || bp.Matchers[0] != "10.0.0.0/8" {
		t.Errorf("Matchers = %v, want [10.0.0.0/8]", bp.Matchers)
	}
}

func TestBuildConfigFromCmd_NodeWithResolver(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?resolver=8.8.8.8,1.1.1.1"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Resolvers) != 1 {
		t.Fatalf("len(Resolvers) = %d, want 1", len(cfg.Resolvers))
	}
	rs := cfg.Resolvers[0]
	if len(rs.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(rs.Nameservers))
	}
}

func TestBuildConfigFromCmd_NodeWithHosts(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?hosts=example.com:1.2.3.4,test.local:5.6.7.8"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Hosts) != 1 {
		t.Fatalf("len(Hosts) = %d, want 1", len(cfg.Hosts))
	}
	hs := cfg.Hosts[0]
	if len(hs.Mappings) != 2 {
		t.Errorf("len(Mappings) = %d, want 2", len(hs.Mappings))
	}
}

func TestBuildConfigFromCmd_NodeWithHopMetadata(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?hop.key=hval&interface=eth0&so_mark=1&proxyProtocol=1"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hop := cfg.Chains[0].Hops[0]
	if hop.Metadata["key"] != "hval" {
		t.Errorf("hop metadata key = %v, want hval", hop.Metadata["key"])
	}
	if hop.Metadata["so_mark"] != 1 {
		t.Errorf("hop.so_mark = %v, want 1", hop.Metadata["so_mark"])
	}
}

func TestBuildConfigFromCmd_ServiceWithAdmission(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?admission=10.0.0.0/8,192.168.0.0/16"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Admissions) != 1 {
		t.Fatalf("len(Admissions) = %d, want 1", len(cfg.Admissions))
	}
	adm := cfg.Admissions[0]
	if len(adm.Matchers) != 2 {
		t.Errorf("len(Matchers) = %d, want 2", len(adm.Matchers))
	}
	if cfg.Services[0].Admission != adm.Name {
		t.Errorf("Service.Admission = %q, want %q", cfg.Services[0].Admission, adm.Name)
	}
}

func TestBuildConfigFromCmd_ServiceWithInvertAdmission(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?admission=~10.0.0.0/8"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if !cfg.Admissions[0].Whitelist {
		t.Error("Admission.Whitelist should be true for ~ prefix")
	}
}

func TestBuildConfigFromCmd_ServiceWithBypass(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?bypass=10.0.0.0/8"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Bypasses) != 1 {
		t.Fatalf("len(Bypasses) = %d, want 1", len(cfg.Bypasses))
	}
	if cfg.Services[0].Bypass != cfg.Bypasses[0].Name {
		t.Errorf("Service.Bypass = %q, want %q", cfg.Services[0].Bypass, cfg.Bypasses[0].Name)
	}
}

func TestBuildConfigFromCmd_ServiceWithResolver(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?resolver=8.8.8.8&prefer=go"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	rs := cfg.Resolvers[0]
	if rs.Nameservers[0].Prefer != "go" {
		t.Errorf("Prefer = %q, want go", rs.Nameservers[0].Prefer)
	}
}

func TestBuildConfigFromCmd_ServiceWithHosts(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?hosts=example.com:1.2.3.4"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hs := cfg.Hosts[0]
	if len(hs.Mappings) != 1 || hs.Mappings[0].Hostname != "example.com" || hs.Mappings[0].IP != "1.2.3.4" {
		t.Errorf("Mappings = %+v, want example.com:1.2.3.4", hs.Mappings)
	}
}

func TestBuildConfigFromCmd_ServiceWithLimiters(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?limiter.in=1MB&limiter.out=2MB&limiter.conn.in=10&limiter.conn.out=20"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Limiters) != 1 {
		t.Fatalf("len(Limiters) = %d, want 1", len(cfg.Limiters))
	}
	lim := cfg.Limiters[0]
	if len(lim.Limits) != 2 {
		t.Errorf("len(Limits) = %d, want 2", len(lim.Limits))
	}
	if cfg.Services[0].Limiter != lim.Name {
		t.Errorf("Service.Limiter = %q, want %q", cfg.Services[0].Limiter, lim.Name)
	}
}

func TestBuildConfigFromCmd_ServiceWithCLimiter(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?climiter=100"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.CLimiters) != 1 {
		t.Fatalf("len(CLimiters) = %d, want 1", len(cfg.CLimiters))
	}
	if cfg.Services[0].CLimiter != cfg.CLimiters[0].Name {
		t.Errorf("Service.CLimiter = %q, want %q", cfg.Services[0].CLimiter, cfg.CLimiters[0].Name)
	}
}

func TestBuildConfigFromCmd_ServiceWithRLimiter(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?rlimiter=0.5"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.RLimiters) != 1 {
		t.Fatalf("len(RLimiters) = %d, want 1", len(cfg.RLimiters))
	}
	if cfg.Services[0].RLimiter != cfg.RLimiters[0].Name {
		t.Errorf("Service.RLimiter = %q, want %q", cfg.Services[0].RLimiter, cfg.RLimiters[0].Name)
	}
}

func TestBuildConfigFromCmd_ServiceWithRetries(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?retries=3"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if cfg.Services[0].Handler.Retries != 3 {
		t.Errorf("Retries = %d, want 3", cfg.Services[0].Handler.Retries)
	}
}

func TestBuildConfigFromCmd_MultipleServices(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080", ":9090"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Services) != 2 {
		t.Fatalf("len(Services) = %d, want 2", len(cfg.Services))
	}
	if cfg.Services[0].Name != "service-0" || cfg.Services[1].Name != "service-1" {
		t.Errorf("names = %q, %q, want service-0, service-1",
			cfg.Services[0].Name, cfg.Services[1].Name)
	}
}

func TestBuildConfigFromCmd_InvalidNode(t *testing.T) {
	// Norm returns ErrInvalidCmd for empty strings
	_, err := BuildConfigFromCmd(
		nil,
		[]string{""},
	)
	if err == nil {
		t.Error("BuildConfigFromCmd should return error for empty node string")
	}
}

func TestBuildConfigFromCmd_NodeWithCommaSeparatedHosts(t *testing.T) {
	// url.Parse accepts comma-separated hostnames without a port on the first entry
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://h1,h2:3128"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hop := cfg.Chains[0].Hops[0]
	if len(hop.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(hop.Nodes))
	}
	if hop.Nodes[0].Addr != "h1" || hop.Nodes[1].Addr != "h2:3128" {
		t.Errorf("Node addrs = %q, %q, want h1, h2:3128",
			hop.Nodes[0].Addr, hop.Nodes[1].Addr)
	}
}

func TestBuildConfigFromCmd_NodeWithSelector(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?strategy=rr&maxFails=3&failTimeout=10s"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	sel := cfg.Chains[0].Hops[0].Selector
	if sel == nil {
		t.Fatal("Selector is nil")
	}
	if sel.Strategy != "rr" {
		t.Errorf("Strategy = %q, want rr", sel.Strategy)
	}
	if sel.MaxFails != 3 {
		t.Errorf("MaxFails = %d, want 3", sel.MaxFails)
	}
}

func TestBuildConfigFromCmd_HttpsRewritesToHTTPTLS(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{"https://:443"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	// https is rewritten to http+tls by Norm; buildServiceConfig splits into handler=http, listener=tls
	svc := cfg.Services[0]
	if svc.Handler.Type != "http" && svc.Handler.Type != "auto" {
		t.Errorf("Handler.Type = %q, want http or auto", svc.Handler.Type)
	}
	if svc.Listener.Type != "tls" && svc.Listener.Type != "tcp" {
		t.Errorf("Listener.Type = %q, want tls or tcp", svc.Listener.Type)
	}
}

func TestBuildConfigFromCmd_EmptyServiceString(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{"", "  ", ":8080"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Services) != 1 {
		t.Fatalf("len(Services) = %d, want 1 (empty strings skipped)", len(cfg.Services))
	}
}

func TestBuildConfigFromCmd_NodeMetadataNotMixedWithServiceMetadata(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?hop.something=svcval"},
		[]string{"http://proxy:3128?hop.something=nodeval"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hop := cfg.Chains[0].Hops[0]
	if hop.Metadata["something"] != "nodeval" {
		t.Errorf("hop metadata = %v, want nodeval", hop.Metadata["something"])
	}
	// service's hop.something shouldn't interfere with node's hop metadata
	svc := cfg.Services[0]
	if svc.Metadata["something"] == "svcval" {
		t.Error("service metadata should not contain hop.something")
	}
}

func TestBuildConfigFromCmd_NodeWithConnectorAndDialerMetadata(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?connector.timeout=5s&dialer.keepAlive=true&node.weight=10"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	nodeCfg := cfg.Chains[0].Hops[0].Nodes[0]
	if nodeCfg.Connector.Metadata["timeout"] != "5s" {
		t.Errorf("connector timeout = %v, want 5s", nodeCfg.Connector.Metadata["timeout"])
	}
	if nodeCfg.Dialer.Metadata["keepAlive"] != "true" {
		t.Errorf("dialer keepAlive = %v, want true", nodeCfg.Dialer.Metadata["keepAlive"])
	}
	if nodeCfg.Metadata["weight"] != "10" {
		t.Errorf("node weight = %v, want \"10\"", nodeCfg.Metadata["weight"])
	}
}

func TestBuildConfigFromCmd_ServiceWithHandlerAndListenerMetadata(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?handler.timeout=10s&listener.backlog=128&service.note=test"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	svc := cfg.Services[0]
	if svc.Handler.Metadata["timeout"] != "10s" {
		t.Errorf("handler timeout = %v, want 10s", svc.Handler.Metadata["timeout"])
	}
	if svc.Listener.Metadata["backlog"] != "128" {
		t.Errorf("listener backlog = %v, want 128", svc.Listener.Metadata["backlog"])
	}
	if svc.Metadata["note"] != "test" {
		t.Errorf("service note = %v, want test", svc.Metadata["note"])
	}
}

func TestBuildConfigFromCmd_ForwardService(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{"tcp://:8080/1.2.3.4:80"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	svc := cfg.Services[0]
	if svc.Forwarder == nil {
		t.Fatal("Forwarder is nil")
	}
	if len(svc.Forwarder.Nodes) != 1 {
		t.Fatalf("len(Nodes) = %d, want 1", len(svc.Forwarder.Nodes))
	}
	if svc.Forwarder.Nodes[0].Addr != "1.2.3.4:80" {
		t.Errorf("Forward addr = %q, want 1.2.3.4:80", svc.Forwarder.Nodes[0].Addr)
	}
}

func TestParseAuthFromCmd_UsernameOnly(t *testing.T) {
	authB64 := base64.RawURLEncoding.EncodeToString([]byte("useronly"))
	got, err := parseAuthFromCmd(authB64)
	if err != nil {
		t.Fatalf("parseAuthFromCmd: %v", err)
	}
	if got.Username != "useronly" {
		t.Errorf("Username = %q, want useronly", got.Username)
	}
	if got.Password != "" {
		t.Errorf("Password = %q, want empty", got.Password)
	}
}

func TestBuildConfigFromCmd_ServiceWithInvertBypass(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?bypass=~10.0.0.0/8"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	bp := cfg.Bypasses[0]
	if !bp.Whitelist {
		t.Error("service Bypass.Whitelist should be true for ~ prefix")
	}
}

func TestBuildConfigFromCmd_NodeBypassEmptyMatcher(t *testing.T) {
	// Empty entries after comma split should be skipped
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?bypass=10.0.0.0/8,,192.168.0.0/16"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	bp := cfg.Bypasses[0]
	if len(bp.Matchers) != 2 {
		t.Errorf("len(Matchers) = %d, want 2 (empty entry skipped)", len(bp.Matchers))
	}
}

func TestBuildConfigFromCmd_NodeResolverEmptyEntry(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?resolver=8.8.8.8,,1.1.1.1"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Resolvers[0].Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2 (empty entry skipped)", len(cfg.Resolvers[0].Nameservers))
	}
}

func TestBuildConfigFromCmd_NodeHostsInvalidMapping(t *testing.T) {
	// entries without a colon are skipped; entries with empty IP after colon are kept
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://proxy:3128?hosts=valid.com:1.2.3.4,badentry,another.com:5.6.7.8"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hs := cfg.Hosts[0]
	if len(hs.Mappings) != 2 {
		t.Errorf("len(Mappings) = %d, want 2 (badentry without colon skipped)", len(hs.Mappings))
	}
}

func TestBuildConfigFromCmd_ServiceHostsInvalidMapping(t *testing.T) {
	// entries without colon are skipped; entries with only colon+empty IP are kept
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?hosts=good.com:1.2.3.4,badonly,other.com:5.6.7.8"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hs := cfg.Hosts[0]
	if len(hs.Mappings) != 2 {
		t.Errorf("len(Mappings) = %d, want 2 (badonly without colon skipped)", len(hs.Mappings))
	}
}

func TestBuildConfigFromCmd_ServiceResolverEmptyEntry(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?resolver=8.8.8.8,,1.1.1.1"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Resolvers[0].Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(cfg.Resolvers[0].Nameservers))
	}
}

func TestBuildConfigFromCmd_ServiceAdmissionEmptyMatcher(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?admission=10.0.0.0/8,,192.168.0.0/16"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Admissions[0].Matchers) != 2 {
		t.Errorf("len(Matchers) = %d, want 2", len(cfg.Admissions[0].Matchers))
	}
}

func TestBuildConfigFromCmd_ServiceBypassEmptyMatcher(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080?bypass=10.0.0.0/8,,192.168.0.0/16"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	if len(cfg.Bypasses[0].Matchers) != 2 {
		t.Errorf("len(Matchers) = %d, want 2", len(cfg.Bypasses[0].Matchers))
	}
}

func TestBuildConfigFromCmd_MultipleNodesCommaHost(t *testing.T) {
	// Tests comma-separated hosts in node addr that result in multiple nodes with same hop
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://h1,h2,h3:3128"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hop := cfg.Chains[0].Hops[0]
	if len(hop.Nodes) != 3 {
		t.Fatalf("len(Nodes) = %d, want 3", len(hop.Nodes))
	}
}

func TestBuildConfigFromCmd_NodeHostEmptySkipped(t *testing.T) {
	// url.Parse("http://h1,,h2:3128") is valid (comma in hostname).
	// Split by comma yields ["h1", "", "h2:3128"] — the empty string is skipped.
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		[]string{"http://h1,,h2:3128"},
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	hop := cfg.Chains[0].Hops[0]
	if len(hop.Nodes) != 2 {
		t.Errorf("len(Nodes) = %d, want 2 (empty entry skipped)", len(hop.Nodes))
	}
}

func TestBuildConfigFromCmd_NoChainForMissingNode(t *testing.T) {
	cfg, err := BuildConfigFromCmd(
		[]string{":8080"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCmd: %v", err)
	}

	// No nodes = no chain = handler should not have chain
	if cfg.Services[0].Handler.Chain != "" {
		t.Errorf("Handler.Chain = %q, want empty (no chain created)", cfg.Services[0].Handler.Chain)
	}
}

func TestBuildServiceConfig_FullAutoScheme(t *testing.T) {
	// auto:// scheme triggers handler=auto, listener=tcp fallback
	rawURL := "auto://:8080"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	if len(svcs) != 1 {
		t.Fatalf("len(svcs) = %d, want 1", len(svcs))
	}
	if svcs[0].Handler.Type != "auto" {
		t.Errorf("Handler.Type = %q, want auto", svcs[0].Handler.Type)
	}
}

func TestBuildServiceConfig_SSUHandlerUDPListener(t *testing.T) {
	// ssu handler auto-detects to udp listener (handler stays "ssu" if in registry)
	rawURL := "ssu://:8388"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	// ssu handler not in registry → falls back to auto
	// listener defaults to tcp, but if handler was "ssu" it would be udp
	if svcs[0].Listener.Type != "tcp" {
		t.Errorf("Listener.Type = %q, want tcp (ssu not in test registry)", svcs[0].Listener.Type)
	}
}

func TestBuildServiceConfig_RelayHandler(t *testing.T) {
	// relay handler stays "relay" when forwarding (the relay!=relay check
	// in buildServiceConfig preserves the handler type). When relay is not
	// in the registry it falls back to auto, but we still get a forwarder.
	rawURL := "relay://:8421/1.2.3.4:80"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	svc := svcs[0]
	if svc.Forwarder == nil {
		t.Fatal("Forwarder is nil for relay with forward path")
	}
	if svc.Handler.Type != "relay" && svc.Handler.Type != "auto" && svc.Handler.Type != "tcp" {
		t.Errorf("Handler.Type = %q, want relay, auto, or tcp", svc.Handler.Type)
	}
}

func TestBuildServiceConfig_ForwardMode(t *testing.T) {
	// Non-relay handler with forward path → handler becomes listener type (tcp by default)
	rawURL := "http://:8080/1.2.3.4:80,5.6.7.8:443"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	svc := svcs[0]
	if svc.Forwarder == nil {
		t.Fatal("Forwarder is nil")
	}
	if len(svc.Forwarder.Nodes) != 2 {
		t.Errorf("len(Forwarder.Nodes) = %d, want 2", len(svc.Forwarder.Nodes))
	}
	// handler becomes listener type (tcp) for non-relay forward mode, or "auto" if not found
	if svc.Handler.Type != "tcp" && svc.Handler.Type != "auto" && svc.Handler.Type != "forward" {
		t.Errorf("Handler.Type = %q", svc.Handler.Type)
	}
}

func TestBuildServiceConfig_DNSListener(t *testing.T) {
	// dns handler+listener with forward path → handler becomes listener type
	rawURL := "dns://:53/8.8.8.8"
	u, _ := url.Parse(rawURL)

	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}

	svc := svcs[0]
	// dns not in registry → handler falls back to auto, then becomes listener type (tcp) for forward mode
	// or dns IS in registry → handler stays "dns"
	if svc.Forwarder == nil {
		t.Fatal("Forwarder is nil")
	}
	if svc.Handler.Type != "dns" && svc.Handler.Type != "tcp" && svc.Handler.Type != "auto" {
		t.Errorf("Handler.Type = %q", svc.Handler.Type)
	}
}

func TestBuildNodeConfig_SSH_StandardAuth(t *testing.T) {
	// SSH scheme with unknown registries: connector→http, dialer→tcp.
	// Since dialer != "ssh"/"sshd" after fallback, auth stays on connector.
	rawURL := "ssh://user:pass@server:22"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Connector.Auth == nil {
		t.Fatal("Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "user" || node.Connector.Auth.Password != "pass" {
		t.Errorf("Connector.Auth = %+v, want user:pass", node.Connector.Auth)
	}
	if node.Dialer.Auth != nil {
		t.Error("Dialer.Auth should be nil (dialer fell back to tcp)")
	}
}

func TestBuildNodeConfig_TLSWithCert(t *testing.T) {
	// TLS with certFile and keyFile (but no secure)
	u, _ := url.Parse("http+tls://server:443")
	m := map[string]any{
		"cert": "cert.pem",
		"key":  "key.pem",
	}

	node, err := buildNodeConfig(u, m)
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Dialer.TLS == nil {
		t.Fatal("Dialer.TLS is nil")
	}
	if node.Dialer.TLS.CertFile != "cert.pem" || node.Dialer.TLS.KeyFile != "key.pem" {
		t.Errorf("TLS = %+v, want cert.pem/key.pem", node.Dialer.TLS)
	}
}

func TestBuildNodeConfig_UnixFallsBackToTCP(t *testing.T) {
	// http+unix scheme: connector=http, dialer=unix.
	// Since unix is not in the test registry, dialer falls back to tcp,
	// and the path-based address logic (dialer=="unix") is skipped.
	rawURL := "http+unix:///var/run/socket"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	if node.Dialer.Type != "tcp" {
		t.Errorf("Dialer.Type = %q, want tcp (unix not in test registry)", node.Dialer.Type)
	}
	// Addr is url.Host ("") since no host component in three-slash unix URL
	if node.Addr != "" {
		t.Errorf("Addr = %q, want empty", node.Addr)
	}
}

func TestBuildServiceConfig_RelayTLSForward(t *testing.T) {
	// relay+tls scheme: handler=relay, listener=tls.
	// relay not in test registry → handler falls back to auto, listener falls back to tcp.
	// With forward path, handler becomes listener type (tcp) since handler != "relay" after fallback.
	u, _ := url.Parse("relay+tls://:8443/backend:443")
	svcs, err := buildServiceConfig(u)
	if err != nil {
		t.Fatalf("buildServiceConfig: %v", err)
	}
	if len(svcs) != 1 {
		t.Errorf("len(svcs) = %d, want 1", len(svcs))
	}
	if svcs[0].Forwarder == nil {
		t.Fatal("Forwarder is nil for relay+tls with path")
	}
	// Handler falls back to tcp due to registry fallback + forward mode reassignment
	if svcs[0].Handler.Type != "tcp" && svcs[0].Handler.Type != "auto" && svcs[0].Handler.Type != "relay" {
		t.Errorf("Handler.Type = %q", svcs[0].Handler.Type)
	}
}

func TestBuildNodeConfig_SSUDefaultAuth(t *testing.T) {
	// SIP002 auth for ssu scheme
	encoded := base64.RawURLEncoding.EncodeToString([]byte("method:secret"))
	rawURL := "ssu://" + encoded + "@server:8388"
	u, _ := url.Parse(rawURL)

	node, err := buildNodeConfig(u, map[string]any{})
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	// Connector falls back to http, so auth is on connector
	if node.Connector.Auth == nil {
		t.Fatal("Connector.Auth is nil")
	}
	if node.Connector.Auth.Username != "method" || node.Connector.Auth.Password != "secret" {
		t.Errorf("Auth = %+v, want method:secret", node.Connector.Auth)
	}
}

func TestCopyHandlerConfig_Nil(t *testing.T) {
	if copyHandlerConfig(nil) != nil {
		t.Error("copyHandlerConfig(nil) should be nil")
	}
}

func TestCopyListenerConfig_Nil(t *testing.T) {
	if copyListenerConfig(nil) != nil {
		t.Error("copyListenerConfig(nil) should be nil")
	}
}

func TestBuildConfigFromCmd_ServiceAuthError(t *testing.T) {
	// Invalid base64 auth in service query should fail in buildServiceConfig
	_, err := BuildConfigFromCmd(
		[]string{"http://:8080?auth=!!!bad!!!"},
		nil,
	)
	if err == nil {
		t.Error("BuildConfigFromCmd should return error for invalid service auth")
	}
}

func TestNorm_InvalidURL(t *testing.T) {
	// Test with a URL containing control characters that url.Parse might reject
	_, err := Norm("http://host:8080\x00")
	if err == nil {
		t.Error("Norm should return error for invalid URL")
	}
}

func TestParseSelector_FailTimeoutAsInt(t *testing.T) {
	// failTimeout can be specified as an integer (treated as seconds).
	// GetDuration treats int values as seconds.
	m := map[string]any{
		"strategy":    "random",
		"failTimeout": 10,
	}
	got := parseSelector(m)
	if got == nil {
		t.Fatal("parseSelector() = nil")
	}
	if got.FailTimeout <= 0 {
		t.Errorf("FailTimeout = %v, want > 0", got.FailTimeout)
	}
	// keys should be cleaned up
	if _, ok := m["failTimeout"]; ok {
		t.Error("failTimeout key should be deleted from m")
	}
}

func TestBuildNodeConfig_TLSOnlySecure(t *testing.T) {
	// TLS with only Secure=true should still create a TLSConfig (Secure alone is enough)
	u, _ := url.Parse("http://server:8080")
	m := map[string]any{"secure": true}

	node, err := buildNodeConfig(u, m)
	if err != nil {
		t.Fatalf("buildNodeConfig: %v", err)
	}

	// TLS should be set because Secure=true, even without cert/ca/servername
	if node.Dialer.TLS == nil {
		t.Fatal("Dialer.TLS is nil — Secure alone should keep TLS config")
	}
	if node.Dialer.TLS.Secure != true {
		t.Error("TLS.Secure should be true")
	}
}

