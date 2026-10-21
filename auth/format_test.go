package auth

import (
	"testing"
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
