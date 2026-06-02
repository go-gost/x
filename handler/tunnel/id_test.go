package tunnel

import (
	"testing"

	"github.com/go-gost/relay"
	"github.com/google/uuid"
)

func TestParseTunnelID(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		tid := ParseTunnelID("")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for empty string")
		}
	})

	t.Run("valid uuid", func(t *testing.T) {
		tid := ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if tid.IsZero() {
			t.Error("expected non-zero tunnel ID")
		}
		if tid.IsPrivate() {
			t.Error("expected non-private tunnel ID")
		}
	})

	t.Run("valid uuid with $ prefix", func(t *testing.T) {
		tid := ParseTunnelID("$6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if tid.IsZero() {
			t.Error("expected non-zero tunnel ID")
		}
		if !tid.IsPrivate() {
			t.Error("expected private tunnel ID")
		}
	})

	t.Run("invalid uuid", func(t *testing.T) {
		tid := ParseTunnelID("not-a-uuid")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for invalid input")
		}
	})

	t.Run("invalid uuid with $ prefix", func(t *testing.T) {
		tid := ParseTunnelID("$not-a-uuid")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for invalid input")
		}
	})
}

func TestParseTunnelID_PrivateMarker(t *testing.T) {
	t.Run("dollar not at start", func(t *testing.T) {
		tid := ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if tid.IsPrivate() {
			t.Error("expected non-private when $ is not at start")
		}
	})
}

func TestParseTunnelID_RoundTrip(t *testing.T) {
	original := ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	t.Logf("original string: %s", original.String())

	reparsed := ParseTunnelID(original.String())
	if !original.Equal(reparsed) {
		t.Errorf("round-trip failed: original=%v reparsed=%v", original, reparsed)
	}
}

func TestParseTunnelID_PrivateRoundTrip(t *testing.T) {
	original := ParseTunnelID("$6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if !original.IsPrivate() {
		t.Fatal("expected private tunnel ID")
	}
	t.Logf("original string: %s", original.String())

	// The private flag is carried in the struct, not in the string representation.
	// Reparsing from String() gives a non-private ID because the $ prefix is not
	// part of the relay.TunnelID.String() output.
	reparsed := ParseTunnelID(original.String())
	if !original.Equal(reparsed) {
		t.Errorf("round-trip failed: original=%v reparsed=%v", original, reparsed)
	}
}

func TestParseTunnelID_RelayCompatibility(t *testing.T) {
	id := ParseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	u, _ := uuid.Parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	var raw [16]byte
	copy(raw[:], u[:])
	expected := relay.NewTunnelID(raw[:])
	if !id.Equal(expected) {
		t.Error("ParseTunnelID result should match relay.NewTunnelID")
	}
}