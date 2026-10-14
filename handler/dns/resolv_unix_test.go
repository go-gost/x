//go:build !windows

package dns

import (
	"os"
	"path/filepath"
	"testing"

	xmd "github.com/go-gost/x/metadata"
)

// TestInit_SystemNameservers covers the middle rung of the Init fallback
// chain: when neither hop nodes nor metadata DNS is configured, nameservers
// from the system config become "system-N" exchangers. It pins the parser
// behavior: comments and other directives are ignored, invalid IPs are
// skipped, a missing port defaults to 53, and an explicit port is kept.
func TestInit_SystemNameservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	content := "# a comment\n" +
		"; another comment\n" +
		"search example.com\n" +
		"nameserver not-an-ip\n" +
		"nameserver 1.1.1.1\n" +
		"nameserver 8.8.8.8:5353\n" +
		"nameserver ::1\n" +
		"options ndots:5\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	restore := resolvConfPath
	resolvConfPath = path
	t.Cleanup(func() { resolvConfPath = restore })

	h := newTestHandler()
	if err := h.Init(xmd.NewMetadata(nil)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if len(h.exchangers) != 3 {
		t.Fatalf("len(exchangers) = %d, want 3", len(h.exchangers))
	}
	if got, want := h.exchangers["system-0"].String(), "udp://1.1.1.1:53"; got != want {
		t.Errorf("system-0 = %q, want %q", got, want)
	}
	if got, want := h.exchangers["system-1"].String(), "udp://8.8.8.8:5353"; got != want {
		t.Errorf("system-1 = %q, want %q", got, want)
	}
	if got, want := h.exchangers["system-2"].String(), "udp://[::1]:53"; got != want {
		t.Errorf("system-2 = %q, want %q", got, want)
	}
}
