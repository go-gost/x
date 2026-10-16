package tun

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every reporting window must name the destination that opened it. Locking the
// report on the very first destination the process ever saw hid a whole class
// of unrouted downlink: a peer's address was discarded under a stale
// "ff02::16" label, and only a burst of traffic made the count betray it.
func TestCountUnroutedNamesEachWindow(t *testing.T) {
	var mu sync.Mutex
	var warns []string
	h := newP2PHub(nil, nil, nil, func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		warns = append(warns, msg)
	})

	old := unroutedWindow
	unroutedWindow = 40 * time.Millisecond
	defer func() { unroutedWindow = old }()

	phone := net.ParseIP("10.10.100.250")
	mld := net.ParseIP("ff02::16")

	h.countUnrouted(mld)   // the process's first miss: reported at once
	h.countUnrouted(phone) // counted into that same window
	time.Sleep(2 * unroutedWindow)
	h.countUnrouted(phone) // closes that window, opens the next
	time.Sleep(2 * unroutedWindow)
	h.countUnrouted(phone) // closes the next window

	mu.Lock()
	defer mu.Unlock()
	if len(warns) < 3 {
		t.Fatalf("got %d reports, want >= 3: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0], mld.String()) {
		t.Fatalf("first report named %q, want %s", warns[0], mld)
	}
	// The second window is the phone's: it is the destination that opened it,
	// so that is the destination the report must name.
	if !strings.Contains(warns[2], phone.String()) {
		t.Fatalf("window report named %q, want it to name %s", warns[2], phone)
	}
	if strings.Contains(warns[2], mld.String()) {
		t.Fatalf("window report still names the stale destination %s: %q", mld, warns[2])
	}
}
