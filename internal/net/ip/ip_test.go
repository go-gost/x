package ip

import (
	"testing"

	"github.com/songgao/water/waterutil"
)

func TestProtocol(t *testing.T) {
	tests := []struct {
		name string
		p    waterutil.IPProtocol
		want string
	}{
		{"HOPOPT", waterutil.HOPOPT, "HOPOPT"},
		{"ICMP", waterutil.ICMP, "ICMP"},
		{"IGMP", waterutil.IGMP, "IGMP"},
		{"GGP", waterutil.GGP, "GGP"},
		{"TCP", waterutil.TCP, "TCP"},
		{"UDP", waterutil.UDP, "UDP"},
		{"IPv6-Route", waterutil.IPv6_Route, "IPv6-Route"},
		{"IPv6-Frag", waterutil.IPv6_Frag, "IPv6-Frag"},
		{"IPv6-ICMP", waterutil.IPv6_ICMP, "IPv6-ICMP"},
		{"unknown protocol", waterutil.IPProtocol(255), "unknown(255)"},
		{"unknown value", waterutil.IPProtocol(100), "unknown(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Protocol(tt.p)
			if got != tt.want {
				t.Errorf("Protocol() = %q, want %q", got, tt.want)
			}
		})
	}
}
