// Package tunnel implements the GOST relay tunnel handler for NAT traversal,
// connecting public entrypoints to internal services behind NAT/firewall.
//
// See handler.go for a full architecture overview.
package tunnel

import (
	"github.com/go-gost/relay"
	"github.com/google/uuid"
)

// ParseTunnelID parses a tunnel ID from a string.
// If s is empty or contains an invalid UUID, the returned tunnel ID is zero
// (callers must check IsZero). A leading '$' prefix marks the tunnel as private.
func ParseTunnelID(s string) (tid relay.TunnelID) {
	if s == "" {
		return
	}
	private := false
	if s[0] == '$' {
		private = true
		s = s[1:]
	}
	u, _ := uuid.Parse(s) // zero ID on error — caller checks IsZero

	if private {
		return relay.NewPrivateTunnelID(u[:])
	}
	return relay.NewTunnelID(u[:])
}