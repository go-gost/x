package v5

import (
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestNetworkAddr(t *testing.T) {
	tests := []struct {
		name    string
		network string
		addr    *gosocks5.Addr
		want    string
	}{
		{
			name:    "nil addr returns unmodified",
			network: "tcp",
			addr:    nil,
			want:    "tcp",
		},
		{
			name:    "IPv4 tcp returns tcp4",
			network: "tcp",
			addr:    &gosocks5.Addr{Type: gosocks5.AddrIPv4},
			want:    "tcp4",
		},
		{
			name:    "IPv6 tcp returns tcp6",
			network: "tcp",
			addr:    &gosocks5.Addr{Type: gosocks5.AddrIPv6},
			want:    "tcp6",
		},
		{
			name:    "IPv4 udp returns udp4",
			network: "udp",
			addr:    &gosocks5.Addr{Type: gosocks5.AddrIPv4},
			want:    "udp4",
		},
		{
			name:    "IPv6 udp returns udp6",
			network: "udp",
			addr:    &gosocks5.Addr{Type: gosocks5.AddrIPv6},
			want:    "udp6",
		},
		{
			name:    "domain addr returns unmodified",
			network: "tcp",
			addr:    &gosocks5.Addr{Type: gosocks5.AddrDomain},
			want:    "tcp",
		},
		{
			name:    "unknown addr type returns unmodified",
			network: "udp",
			addr:    &gosocks5.Addr{Type: 99},
			want:    "udp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := networkAddr(tt.network, tt.addr)
			if got != tt.want {
				t.Errorf("networkAddr(%q, %v) = %q, want %q", tt.network, tt.addr, got, tt.want)
			}
		})
	}
}
