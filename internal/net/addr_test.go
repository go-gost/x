package net

import (
	"net"
	"net/netip"
	"testing"
)

func TestPortRange_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin int
		wantMax int
		wantErr bool
	}{
		{"single port", "8080", 8080, 8080, false},
		{"range", "8000-9000", 8000, 9000, false},
		{"zero", "0", 0, 0, false},
		{"max port", "65535", 65535, 65535, false},
		{"negative", "-1", 0, 0, true},
		{"too large", "65536", 0, 0, true},
		{"three parts", "1-2-3", 0, 0, true},
		{"invalid string", "abc", 0, 0, true},
		{"invalid min", "abc-123", 0, 0, true},
		{"invalid max", "123-abc", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pr PortRange
			err := pr.Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pr.Min != tt.wantMin || pr.Max != tt.wantMax {
					t.Errorf("Parse() got Min=%d Max=%d, want Min=%d Max=%d", pr.Min, pr.Max, tt.wantMin, tt.wantMax)
				}
			}
		})
	}
}

func TestPortRange_Contains(t *testing.T) {
	pr := PortRange{Min: 8000, Max: 9000}
	if !pr.Contains(8000) {
		t.Error("should contain min")
	}
	if !pr.Contains(9000) {
		t.Error("should contain max")
	}
	if !pr.Contains(8500) {
		t.Error("should contain middle")
	}
	if pr.Contains(7999) {
		t.Error("should not contain below min")
	}
	if pr.Contains(9001) {
		t.Error("should not contain above max")
	}
}

func TestIPRange_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin string
		wantMax string
		wantErr bool
	}{
		{"single ipv4", "192.168.1.1", "192.168.1.1", "192.168.1.1", false},
		{"ipv4 range", "192.168.1.1-192.168.1.254", "192.168.1.1", "192.168.1.254", false},
		{"single ipv6", "::1", "::1", "::1", false},
		{"ipv6 range", "::1-::2", "::1", "::2", false},
		{"three parts", "1-2-3", "", "", true},
		{"invalid single", "not-an-ip", "", "", true},
		{"invalid min", "not-ip-192.168.1.2", "", "", true},
		{"invalid max", "192.168.1.1-not-ip", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r IPRange
			err := r.Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				wantMin := netip.MustParseAddr(tt.wantMin)
				wantMax := netip.MustParseAddr(tt.wantMax)
				if r.Min != wantMin || r.Max != wantMax {
					t.Errorf("Parse() got Min=%v Max=%v, want Min=%v Max=%v", r.Min, r.Max, wantMin, wantMax)
				}
			}
		})
	}
}

func TestIPRange_Contains(t *testing.T) {
	r := IPRange{
		Min: netip.MustParseAddr("192.168.1.0"),
		Max: netip.MustParseAddr("192.168.1.255"),
	}
	if !r.Contains(netip.MustParseAddr("192.168.1.0")) {
		t.Error("should contain min")
	}
	if !r.Contains(netip.MustParseAddr("192.168.1.255")) {
		t.Error("should contain max")
	}
	if !r.Contains(netip.MustParseAddr("192.168.1.100")) {
		t.Error("should contain middle")
	}
	if r.Contains(netip.MustParseAddr("192.168.0.255")) {
		t.Error("should not contain below min")
	}
	if r.Contains(netip.MustParseAddr("192.168.2.0")) {
		t.Error("should not contain above max")
	}
}

func TestAddrPortRange_Addrs(t *testing.T) {
	tests := []struct {
		name string
		apr  AddrPortRange
		want []string
	}{
		{"with scheme", "http://192.168.1.1:8080", nil},
		{"tls scheme", "tls://192.168.1.1:8080", nil},
		{"invalid format", "not-a-valid-address", nil},
		{"single port", "192.168.1.1:8080", []string{"192.168.1.1:8080"}},
		{"port range", "192.168.1.1:8080-8082", []string{"192.168.1.1:8080", "192.168.1.1:8081", "192.168.1.1:8082"}},
		{"ipv6 single", "[::1]:8080", []string{"[::1]:8080"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.apr.Addrs()
			if len(got) != len(tt.want) {
				t.Errorf("Addrs() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Addrs()[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func Test_ipToAddr(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	tests := []struct {
		network string
		want    net.Addr
	}{
		{"tcp", &net.TCPAddr{IP: ip, Port: 0}},
		{"tcp4", &net.TCPAddr{IP: ip, Port: 0}},
		{"tcp6", &net.TCPAddr{IP: ip, Port: 0}},
		{"udp", &net.UDPAddr{IP: ip, Port: 0}},
		{"udp4", &net.UDPAddr{IP: ip, Port: 0}},
		{"udp6", &net.UDPAddr{IP: ip, Port: 0}},
		{"ip", &net.IPAddr{IP: ip}},
		{"other", &net.IPAddr{IP: ip}},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			got := ipToAddr(ip, tt.network)
			if got.Network() != tt.want.Network() || got.String() != tt.want.String() {
				t.Errorf("ipToAddr() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_findInterfaceByIP(t *testing.T) {
	// Test with localhost IP
	ip := net.ParseIP("127.0.0.1")
	name, err := findInterfaceByIP(ip)
	if err != nil {
		t.Fatal(err)
	}
	// 127.0.0.1 should be on the loopback interface
	if name == "" {
		t.Log("127.0.0.1 not found on any interface (may happen in containers)")
	}

	// Test with an IP that shouldn't be assigned
	ip2 := net.ParseIP("203.0.113.1")
	name2, err2 := findInterfaceByIP(ip2)
	if err2 != nil {
		t.Fatal(err2)
	}
	if name2 != "" {
		t.Errorf("expected empty name for unassigned IP, got %s", name2)
	}
}

func TestParseInterfaceAddr(t *testing.T) {
	// Empty interface name
	ifce, addrs, isIP, err := ParseInterfaceAddr("", "tcp")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ifce != "" {
		t.Errorf("expected empty ifce, got %s", ifce)
	}
	if isIP {
		t.Errorf("expected isIP=false for empty string, got true")
	}
	if len(addrs) != 1 || addrs[0] != nil {
		t.Errorf("expected [nil], got %v", addrs)
	}

	// Non-existent interface
	_, _, _, err = ParseInterfaceAddr("nonexistent_interface_xyz", "tcp")
	if err == nil {
		t.Error("expected error for non-existent interface")
	}

	// IP string as interface name — isIP should be true
	ifce, addrs, isIP, err = ParseInterfaceAddr("127.0.0.1", "tcp")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !isIP {
		t.Errorf("expected isIP=true for IP input, got false")
	}
	if ifce == "" {
		t.Log("127.0.0.1 not found on any interface (may happen in containers)")
	} else if len(addrs) != 1 {
		t.Errorf("expected 1 addr, got %d", len(addrs))
	}

	// IP that doesn't exist on any interface — should still have isIP=true
	ifce, addrs, isIP, err = ParseInterfaceAddr("203.0.113.1", "udp")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !isIP {
		t.Errorf("expected isIP=true for IP input, got false")
	}
	if ifce != "" {
		t.Errorf("expected empty ifce for unassigned IP, got %s", ifce)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 addr, got %d", len(addrs))
	}

	// Test UDP network specific returns
	ifce, addrs, isIP, err = ParseInterfaceAddr("127.0.0.1", "udp")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !isIP {
		t.Errorf("expected isIP=true for IP input, got false")
	}
	if ifce != "" {
		if len(addrs) != 1 {
			t.Errorf("expected 1 addr, got %d", len(addrs))
		}
	}
}
