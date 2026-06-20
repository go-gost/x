package listener_test

import (
	"net"
	"testing"
	"time"

	admission_wrapper "github.com/go-gost/x/admission/wrapper"
	limiter_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics_wrapper "github.com/go-gost/x/metrics/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
)

// TestWrapUDPConnChainNoCrashWithNilConfigs verifies that chaining
// WrapUDPConn calls with nil optional configs (stats, admission, limiter)
// does not produce a wrapper with a nil internal PacketConn.
//
// Regression test for go-gost/gost#873 — stats.WrapUDPConn returning nil
// when stats is nil, which then entered admission.WrapUDPConn with a nil
// PacketConn, causing a nil-pointer dereference in service.Serve().
func TestWrapUDPConnChainNoCrashWithNilConfigs(t *testing.T) {
	// Simulate a listener's Init() chaining: metrics → stats → admission → limiter.
	pc := &fakePacketConn{}

	// Step 1: metrics.WrapUDPConn — always returns non-nil for non-nil input.
	uc := metrics_wrapper.WrapUDPConn("test-service", pc)
	if uc == nil {
		t.Fatal("metrics.WrapUDPConn returned nil for non-nil input")
	}
	if uc.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil after metrics wrapper")
	}

	// Step 2: stats.WrapUDPConn with nil stats — must NOT return nil.
	uc = stats_wrapper.WrapUDPConn(uc, nil)
	if uc == nil {
		t.Fatal("stats.WrapUDPConn returned nil for nil stats (bug — should return original)")
	}
	if uc.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil after stats wrapper with nil stats")
	}

	// Step 3: admission.WrapUDPConn with nil admission — must NOT return nil.
	uc = admission_wrapper.WrapUDPConn(nil, uc)
	if uc == nil {
		t.Fatal("admission.WrapUDPConn returned nil for nil admission (bug — should return original)")
	}
	if uc.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil after admission wrapper with nil admission")
	}

	// Step 4: limiter.WrapUDPConn with nil limiter — must NOT return nil.
	uc = limiter_wrapper.WrapUDPConn(uc, nil, "key")
	if uc == nil {
		t.Fatal("limiter.WrapUDPConn returned nil for nil limiter (bug — should return original)")
	}
	if uc.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil after limiter wrapper with nil limiter")
	}
}

// TestWrapUDPConnNilInputReturnsNil verifies that all WrapUDPConn variants
// return nil when given a nil net.PacketConn (defensive guard).
func TestWrapUDPConnNilInputReturnsNil(t *testing.T) {
	if v := metrics_wrapper.WrapUDPConn("test", nil); v != nil {
		t.Error("metrics.WrapUDPConn(nil) should return nil")
	}
	if v := stats_wrapper.WrapUDPConn(nil, nil); v != nil {
		t.Error("stats.WrapUDPConn(nil, nil) should return nil")
	}
	if v := admission_wrapper.WrapUDPConn(nil, nil); v != nil {
		t.Error("admission.WrapUDPConn(nil, nil) should return nil")
	}
	if v := limiter_wrapper.WrapUDPConn(nil, nil, ""); v != nil {
		t.Error("limiter.WrapUDPConn(nil, nil, '') should return nil")
	}
}

// fakePacketConn is a minimal net.PacketConn for testing wrapper chains.
type fakePacketConn struct{}

func (c *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}
func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}
func (c *fakePacketConn) Close() error                       { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                { return &fakeAddr{} }
func (c *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error  { return nil }

type fakeAddr struct{}

func (a *fakeAddr) Network() string { return "udp" }
func (a *fakeAddr) String() string  { return "127.0.0.1:0" }
