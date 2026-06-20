//go:build !windows

package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// systemNameservers reads the system DNS configuration from /etc/resolv.conf
// and returns the nameserver addresses as URL-like strings suitable for
// exchanger.NewExchanger (e.g., "udp://1.1.1.1:53").
// Returns nil if the file cannot be read or contains no nameserver entries.
func systemNameservers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr := fields[1]
		// Verify it's a valid IP address.
		if ip := net.ParseIP(addr); ip == nil {
			continue
		}
		// If no port, default to 53.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		servers = append(servers, fmt.Sprintf("udp://%s", addr))
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return servers
}
