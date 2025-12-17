package tungo

import (
	"net/netip"
	"testing"
	"time"
)

func TestConntrackTable_PutGetExpire(t *testing.T) {
	ct := newConntrackTable()
	k := flowKey{
		proto:   flowProtoTCP,
		srcIP:   netip.MustParseAddr("10.0.0.2"),
		dstIP:   netip.MustParseAddr("1.2.3.4"),
		srcPort: 12345,
		dstPort: 443,
	}

	base := time.Unix(1000, 0)
	ct.Put(base, k, flowPolicy{useProxy: true}, 2*time.Second)

	if p, ok := ct.Get(base.Add(1500*time.Millisecond), k); !ok || !p.useProxy {
		t.Fatalf("expected hit useProxy=true, got ok=%v policy=%+v", ok, p)
	}

	if _, ok := ct.Get(base.Add(2500*time.Millisecond), k); ok {
		t.Fatalf("expected expired miss")
	}

	// after expiry, entry should be gone
	if _, ok := ct.Get(base.Add(3*time.Second), k); ok {
		t.Fatalf("expected miss after deletion")
	}
}

func TestConntrackTable_TouchExtendsTTL(t *testing.T) {
	ct := newConntrackTable()
	k := flowKey{
		proto:   flowProtoUDP,
		srcIP:   netip.MustParseAddr("10.0.0.2"),
		dstIP:   netip.MustParseAddr("8.8.8.8"),
		srcPort: 55555,
		dstPort: 53,
	}

	base := time.Unix(2000, 0)
	ct.Put(base, k, flowPolicy{useProxy: false}, 2*time.Second)

	// Extend at t=+1500ms by another 2s
	ct.Touch(base.Add(1500*time.Millisecond), k, 2*time.Second)

	if _, ok := ct.Get(base.Add(2500*time.Millisecond), k); !ok {
		t.Fatalf("expected hit after touch")
	}
	if _, ok := ct.Get(base.Add(4*time.Second), k); ok {
		t.Fatalf("expected miss after extended ttl")
	}
}

func TestConntrackTable_Cleanup(t *testing.T) {
	ct := newConntrackTable()
	base := time.Unix(3000, 0)

	k1 := flowKey{proto: flowProtoTCP, srcIP: netip.MustParseAddr("10.0.0.1"), dstIP: netip.MustParseAddr("1.1.1.1"), srcPort: 1, dstPort: 2}
	k2 := flowKey{proto: flowProtoTCP, srcIP: netip.MustParseAddr("10.0.0.2"), dstIP: netip.MustParseAddr("1.1.1.1"), srcPort: 3, dstPort: 4}

	ct.Put(base, k1, flowPolicy{useProxy: true}, 1*time.Second)
	ct.Put(base, k2, flowPolicy{useProxy: false}, 10*time.Second)

	removed := ct.Cleanup(base.Add(2 * time.Second))
	if removed != 1 {
		t.Fatalf("expected removed=1, got %d", removed)
	}
	if _, ok := ct.Get(base.Add(2*time.Second), k1); ok {
		t.Fatalf("expected k1 removed")
	}
	if _, ok := ct.Get(base.Add(2*time.Second), k2); !ok {
		t.Fatalf("expected k2 still present")
	}
}
