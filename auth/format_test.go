package auth

import (
	"context"
	"errors"
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
