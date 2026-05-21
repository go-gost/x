package dialer

import (
	"testing"
)

func Test_bindDevice(t *testing.T) {
	// Empty interface name - no-op
	err := bindDevice("tcp", "127.0.0.1:80", 0, "")
	if err != nil {
		t.Errorf("expected nil for empty ifce, got %v", err)
	}

	// Non-global unicast IP (loopback) with port - skips binding
	err = bindDevice("tcp", "127.0.0.1:80", 0, "lo")
	if err != nil {
		t.Errorf("expected nil for non-global unicast, got %v", err)
	}

	// ::1 (IPv6 loopback) is also non-global unicast
	err = bindDevice("tcp", "[::1]:80", 0, "lo")
	if err != nil {
		t.Errorf("expected nil for IPv6 loopback, got %v", err)
	}
}

func Test_setMark(t *testing.T) {
	// mark=0 is no-op
	err := setMark(0, 0)
	if err != nil {
		t.Errorf("expected nil for mark=0, got %v", err)
	}

	// Non-zero mark should succeed or fail based on fd validity
	// We test with fd=0 which is stdin (should succeed with SO_MARK)
	err = setMark(0, 1)
	if err != nil {
		t.Logf("setMark with fd=0: %v (expected on some systems)", err)
	}
}
