package cmd

import (
	"encoding/base64"
	"net/url"
	"testing"
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
