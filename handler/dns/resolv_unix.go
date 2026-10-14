//go:build !windows

package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// resolvConfPath is the file systemNameservers reads. It is a var so tests
// can redirect it: the system DNS configuration is per-environment, and
// tests exercising the Init fallback chain must be hermetic against the
// host's (or CI runner's) resolv.conf.
var resolvConfPath = "/etc/resolv.conf"

// systemNameservers reads the system DNS configuration from /etc/resolv.conf
// and returns the nameserver addresses as URL-like strings suitable for
// exchanger.NewExchanger (e.g., "udp://1.1.1.1:53").
// Returns nil if the file cannot be read or contains no nameserver entries.
func systemNameservers() []string {
	f, err := os.Open(resolvConfPath)
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
		// The port is optional in resolv.conf; default it to 53 when
		// absent. Validate the host part only: net.ParseIP rejects a
		// host:port string, so validating addr itself would drop every
		// nameserver that carries an explicit port.
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port == "" {
			host, port = addr, "53"
		}
		if ip := net.ParseIP(host); ip == nil {
			continue
		}
		servers = append(servers, fmt.Sprintf("udp://%s", net.JoinHostPort(host, port)))
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return servers
}
