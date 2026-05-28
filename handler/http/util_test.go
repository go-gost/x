package http

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"testing"
)

func TestDecodeServerName(t *testing.T) {
	// Helper: encode a hostname using the GOST v2 encoding scheme
	encodeName := func(name string) string {
		v := []byte(name)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, crc32.ChecksumIEEE(v))
		inner := base64.RawURLEncoding.EncodeToString(v)
		return base64.RawURLEncoding.EncodeToString(append(b, []byte(inner)...))
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid hostname",
			input: encodeName("example.com:8080"),
			want:  "example.com:8080",
		},
		{
			name:  "valid IP address",
			input: encodeName("1.2.3.4:443"),
			want:  "1.2.3.4:443",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "!!!not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "too short (less than 4 bytes)",
			input:   base64.RawURLEncoding.EncodeToString([]byte("ab")),
			wantErr: true,
		},
		{
			name:    "valid base64 but inner is garbage",
			input:   base64.RawURLEncoding.EncodeToString([]byte("0000!!!!")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeServerName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeServerName(%q) = (%q, nil), want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeServerName(%q) error = %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("decodeServerName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeServerName_CRC32Mismatch(t *testing.T) {
	name := "test.example.com"
	v := []byte(name)
	// Use wrong CRC32
	badCRC := crc32.ChecksumIEEE(v) ^ 0xFFFFFFFF
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, badCRC)
	inner := base64.RawURLEncoding.EncodeToString(v)
	s := base64.RawURLEncoding.EncodeToString(append(b, []byte(inner)...))

	_, err := decodeServerName(s)
	if err == nil {
		t.Error("expected error for CRC32 mismatch")
	}
}

func TestBasicProxyAuth(t *testing.T) {
	encode := func(u, p string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
	}

	tests := []struct {
		name      string
		proxyAuth string
		wantUser  string
		wantPass  string
		wantOK    bool
	}{
		{
			name:      "valid basic auth",
			proxyAuth: encode("admin", "secret"),
			wantUser:  "admin",
			wantPass:  "secret",
			wantOK:    true,
		},
		{
			name:      "username only, no password",
			proxyAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:")),
			wantUser:  "user",
			wantPass:  "",
			wantOK:    true,
		},
		{
			name:      "password only, no username",
			proxyAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte(":pass")),
			wantUser:  "",
			wantPass:  "pass",
			wantOK:    true,
		},
		{
			name:      "password contains colon",
			proxyAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:a:b:c")),
			wantUser:  "user",
			wantPass:  "a:b:c",
			wantOK:    true,
		},
		{
			name:      "empty string",
			proxyAuth: "",
		},
		{
			name:      "not Basic scheme",
			proxyAuth: "Bearer token123",
		},
		{
			name:      "invalid base64",
			proxyAuth: "Basic not-valid-base64!",
		},
		{
			name:      "no colon separator",
			proxyAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte("username")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, ok := basicProxyAuth(tt.proxyAuth)
			if ok != tt.wantOK {
				t.Errorf("basicProxyAuth(%q) ok = %v, want %v", tt.proxyAuth, ok, tt.wantOK)
				return
			}
			if ok {
				if user != tt.wantUser {
					t.Errorf("basicProxyAuth(%q) user = %q, want %q", tt.proxyAuth, user, tt.wantUser)
				}
				if pass != tt.wantPass {
					t.Errorf("basicProxyAuth(%q) pass = %q, want %q", tt.proxyAuth, pass, tt.wantPass)
				}
			}
		})
	}
}

func TestUpgradeType(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name:   "nil header",
			header: nil,
			want:   "",
		},
		{
			name: "websocket upgrade",
			header: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"websocket"},
			},
			want: "websocket",
		},
		{
			name: "http2 upgrade",
			header: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"h2c"},
			},
			want: "h2c",
		},
		{
			name: "no connection upgrade header",
			header: http.Header{
				"Upgrade": {"websocket"},
			},
			want: "",
		},
		{
			name:   "empty header",
			header: http.Header{},
			want:   "",
		},
		{
			name: "connection has upgrade but no upgrade header",
			header: http.Header{
				"Connection": {"Upgrade"},
			},
			want: "",
		},
		{
			name: "connection upgrade in multi-value",
			header: http.Header{
				"Connection": {"keep-alive", "Upgrade"},
				"Upgrade":    {"websocket"},
			},
			want: "websocket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := upgradeType(tt.header); got != tt.want {
				t.Errorf("upgradeType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		defaultPort string
		want        string
	}{
		{
			name:        "hostname without port",
			host:        "example.com",
			defaultPort: "80",
			want:        "example.com:80",
		},
		{
			name:        "hostname with port",
			host:        "example.com:8080",
			defaultPort: "80",
			want:        "example.com:8080",
		},
		{
			name:        "IPv4 without port",
			host:        "1.2.3.4",
			defaultPort: "80",
			want:        "1.2.3.4:80",
		},
		{
			name:        "IPv4 with port",
			host:        "1.2.3.4:443",
			defaultPort: "80",
			want:        "1.2.3.4:443",
		},
		{
			name:        "IPv6 without port (bracketed)",
			host:        "[::1]",
			defaultPort: "80",
			want:        "[::1]:80",
		},
		{
			name:        "IPv6 with port",
			host:        "[::1]:443",
			defaultPort: "80",
			want:        "[::1]:443",
		},
		{
			name:        "empty string",
			host:        "",
			defaultPort: "80",
			want:        ":80",
		},
		{
			name:        "custom default port",
			host:        "example.com",
			defaultPort: "443",
			want:        "example.com:443",
		},
		{
			name:        "bare IPv6 without brackets or port",
			host:        "::1",
			defaultPort: "80",
			want:        "[::1]:80", // net.JoinHostPort wraps IPv6 in brackets
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHostPort(tt.host, tt.defaultPort); got != tt.want {
				t.Errorf("normalizeHostPort(%q, %q) = %q, want %q", tt.host, tt.defaultPort, got, tt.want)
			}
		})
	}
}

func TestBuildConnectResponse(t *testing.T) {
	got := buildConnectResponse("gost/3.0")
	if len(got) == 0 {
		t.Error("buildConnectResponse returned empty")
	}
	s := string(got)
	if !contains(s, "200") {
		t.Errorf("expected 200 status in response: %s", s)
	}
	if !contains(s, "Connection established") {
		t.Errorf("expected Connection established in response: %s", s)
	}
	if !contains(s, "gost/3.0") {
		t.Errorf("expected proxy agent in response: %s", s)
	}
}

func TestBuildConnectResponse_CustomAgent(t *testing.T) {
	got := buildConnectResponse("custom-agent/1.0")
	s := string(got)
	if !contains(s, "custom-agent/1.0") {
		t.Errorf("expected custom agent in response: %s", s)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
