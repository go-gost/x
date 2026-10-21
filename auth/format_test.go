package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	xlogger "github.com/go-gost/x/logger"
)

// A nil reader must never panic, whatever the format. encoding/json panics
// when it is handed a nil io.Reader, and the panic happened in the reload
// goroutine, taking the whole process down.
func TestParseAuthsFormat_NilReader(t *testing.T) {
	for _, format := range []string{"", "text", "json", "yml", "yaml"} {
		t.Run("format="+format, func(t *testing.T) {
			p := &authenticator{options: options{fileFormat: format}}
			m, err := p.parseFileAuths(nil)
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if m != nil {
				t.Fatalf("m = %v, want nil", m)
			}
		})
	}
}

// The file loader returns a nil reader when it fails. That must not panic
// and must not produce a nil map, because the other loaders merge into it.
func TestLoad_FileLoaderErrorWithJSONFormat(t *testing.T) {
	p := &authenticator{
		options: options{
			fileLoader: &mockLoader{loadErr: errors.New("no such file or directory")},
			fileFormat: "json",
		},
		logger: xlogger.Nop(),
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	m, err := p.load(context.Background())
	if err == nil {
		t.Fatal("want a load error")
	}
	if m == nil {
		t.Fatal("m is nil: a later maps.Copy would panic")
	}
}

// The http loader returns a nil reader when the URL is unreachable or
// answers with a non-200 status. That must not panic either.
func TestLoad_HTTPLoaderErrorWithJSONFormat(t *testing.T) {
	p := &authenticator{
		options: options{
			httpLoader: &mockLoader{loadErr: errors.New("connection refused")},
			httpFormat: "json",
		},
		logger: xlogger.Nop(),
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	m, err := p.load(context.Background())
	if err == nil {
		t.Fatal("want a load error")
	}
	if m == nil {
		t.Fatal("m is nil: a later maps.Copy would panic")
	}
}

func TestValidateFormat(t *testing.T) {
	for _, format := range []string{"", " ", "text", "TEXT", " json ", "json", "yaml", "YML", "yml"} {
		if err := ValidateFormat(format); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", format, err)
		}
	}
	for _, format := range []string{"toml", "xml", "csv", "jsonn"} {
		if err := ValidateFormat(format); err == nil {
			t.Errorf("ValidateFormat(%q) = nil, want an error", format)
		}
	}
}

// The structured formats must accept the same credentials as the text
// format, so that moving a file from one to the other does not change
// which users can authenticate.
func TestParseFileAuths_WhitespaceParity(t *testing.T) {
	text := &authenticator{}
	tm, err := text.parseFileAuths(strings.NewReader("alice\tsecret\n"))
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			var data string
			if format == "json" {
				data = `{"auths":[{"username":" alice ","password":" secret "}]}`
			} else {
				data = "auths:\n  - username: \" alice \"\n    password: \" secret \"\n"
			}
			p := &authenticator{options: options{fileFormat: format}}
			m, err := p.parseFileAuths(strings.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(m) != len(tm) {
				t.Fatalf("m = %v, want %v", m, tm)
			}
			for k, v := range tm {
				if m[k] != v {
					t.Fatalf("m = %v, want %v", m, tm)
				}
			}
		})
	}
}

// The per-user "file" field of config.AuthConfig is not supported by the
// structured formats; the password always comes from the "password" field.
func TestParseFileAuths_StructuredIgnoresAuthFileField(t *testing.T) {
	p := &authenticator{options: options{fileFormat: "json"}}
	m, err := p.parseFileAuths(strings.NewReader(
		`{"auths":[{"username":"alice","password":"secret","file":"/etc/gost/alice.key"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m["alice"] != "secret" {
		t.Fatalf("m = %v, want the password field", m)
	}
}

// A YAML decode error carries the offending source lines, which may include
// passwords. The logged message must not contain them.
func TestRedactAuthError(t *testing.T) {
	p := &authenticator{options: options{fileFormat: "yaml"}}
	_, err := p.parseFileAuths(strings.NewReader(
		"auths:\n  - username: admin\n    password: \"s3cr3t\n"))
	if err == nil {
		t.Fatal("want a parse error")
	}
	// The raw goccy error carries the offending source line.
	if !strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("expected the raw error to contain the source line, got: %v", err)
	}
	redacted := redactAuthError(err)
	if strings.Contains(redacted.Error(), "s3cr3t") {
		t.Fatalf("the redacted error leaks the password: %v", redacted)
	}
	if redacted.Error() == "" {
		t.Fatal("the redacted error is empty")
	}
	t.Logf("raw:     %v", err)
	t.Logf("redacted: %s", redacted.Error())
}

// A JSON decode error does not carry the source, so it is passed through
// unchanged.
func TestRedactAuthError_Passthrough(t *testing.T) {
	p := &authenticator{options: options{fileFormat: "json"}}
	_, err := p.parseFileAuths(strings.NewReader(`{"auths":[`))
	if err == nil {
		t.Fatal("want a parse error")
	}
	if got := redactAuthError(err); got.Error() != err.Error() {
		t.Fatalf("got %v, want %v", got, err)
	}
}

// A failing file loader followed by a working http loader must not panic on
// the nil map.
func TestLoad_FailedFileLoaderThenWorkingHTTPLoader(t *testing.T) {
	for _, format := range []string{"text", "json", "yaml"} {
		t.Run("format="+format, func(t *testing.T) {
			p := &authenticator{
				options: options{
					fileLoader: &mockLoader{loadErr: errors.New("no such file or directory")},
					fileFormat: format,
					httpLoader: &mockLoader{loadData: "alice\tsecret\n"},
					httpFormat: "text",
				},
				logger: xlogger.Nop(),
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			m, _ := p.load(context.Background())
			if m["alice"] != "secret" {
				t.Fatalf("m = %v, want the http credentials", m)
			}
		})
	}
}
