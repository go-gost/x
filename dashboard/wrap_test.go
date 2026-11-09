package dashboard

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/resolver"
)

type fakeBypass struct{ match bool }

func (f *fakeBypass) IsWhitelist() bool { return false }
func (f *fakeBypass) Contains(context.Context, string, string, ...bypass.Option) bool {
	return f.match
}

type fakeAdmission struct{ allow bool }

func (f *fakeAdmission) Admit(context.Context, string, string, ...admission.Option) bool {
	return f.allow
}

type fakeHosts struct {
	ips []net.IP
	ok  bool
}

func (f *fakeHosts) Lookup(context.Context, string, string, ...hosts.Option) ([]net.IP, bool) {
	return f.ips, f.ok
}

type fakeResolver struct {
	ips []net.IP
	err error
}

func (f *fakeResolver) Resolve(context.Context, string, string, ...resolver.Option) ([]net.IP, error) {
	return f.ips, f.err
}

func TestWrapBypassRecordsPerService(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	bp := WrapBypass("direct", &fakeBypass{match: true})
	bp.Contains(context.Background(), "tcp", "example.com", bypass.WithService("svc-a"))
	bp.Contains(context.Background(), "tcp", "example.com", bypass.WithService("svc-b"))
	Flush()

	snap := Default().Snapshot()
	a := moduleStats(t, snap, "bypass", "direct", "svc-a")
	b := moduleStats(t, snap, "bypass", "direct", "svc-b")
	if a.Calls != 1 || a.Hits != 1 {
		t.Fatalf("svc-a = %+v", a)
	}
	if b.Calls != 1 || b.Hits != 1 {
		t.Fatalf("svc-b = %+v", b)
	}
}

func TestWrapAdmissionRecordsDenyAsMiss(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	adm := WrapAdmission("lan", &fakeAdmission{allow: false})
	adm.Admit(context.Background(), "tcp", "10.0.0.1:1", admission.WithService("svc"))
	Flush()

	got := moduleStats(t, Default().Snapshot(), "admission", "lan", "svc")
	if got.Calls != 1 || got.Misses != 1 || got.Hits != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestWrapHostsAndResolverAreShared(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	WrapHosts("local", &fakeHosts{ips: []net.IP{net.ParseIP("127.0.0.1")}, ok: true}).
		Lookup(context.Background(), "ip", "example.com")
	WrapResolver("local", &fakeResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}).
		Resolve(context.Background(), "ip", "example.com")
	Flush()

	snap := Default().Snapshot()
	if got := moduleStats(t, snap, "hosts", "local", ""); got.Calls != 1 || got.Hits != 1 {
		t.Fatalf("hosts = %+v", got)
	}
	if got := moduleStats(t, snap, "resolver", "local", ""); got.Calls != 1 || got.Hits != 1 {
		t.Fatalf("resolver = %+v", got)
	}
}

func TestWrapResolverErrorCountsAndEmitsEvent(t *testing.T) {
	ResetState()
	Enable(true)
	defer Enable(false)

	WrapResolver("local", &fakeResolver{err: errors.New("boom")}).
		Resolve(context.Background(), "ip", "example.com")
	Flush()

	snap := Default().Snapshot()
	if got := moduleStats(t, snap, "resolver", "local", ""); got.Errors != 1 {
		t.Fatalf("errors = %d, want 1", got.Errors)
	}
	if len(snap.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(snap.Events))
	}
}

func TestModuleWrappersDisabledReturnNext(t *testing.T) {
	Enable(false)

	bp := &fakeBypass{}
	if got := WrapBypass("direct", bp); got != bp {
		t.Fatal("disabled dashboard must return the original bypass")
	}
	adm := &fakeAdmission{}
	if got := WrapAdmission("lan", adm); got != adm {
		t.Fatal("disabled dashboard must return the original admission")
	}
	hm := &fakeHosts{}
	if got := WrapHosts("local", hm); got != hm {
		t.Fatal("disabled dashboard must return the original host mapper")
	}
	rs := &fakeResolver{}
	if got := WrapResolver("local", rs); got != rs {
		t.Fatal("disabled dashboard must return the original resolver")
	}
}
