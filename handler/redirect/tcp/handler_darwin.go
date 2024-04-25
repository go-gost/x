package redirect

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func (h *redirectHandler) getOriginalDstAddr(conn net.Conn) (addr net.Addr, err error) {
	host, port, err := localToRemote(conn)
	if err != nil {
		return nil, err
	}
	portNumber, _ := strconv.Atoi(port)
	addr = &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: portNumber,
	}

	return
}

func localToRemote(clientConn net.Conn) (string, string, error) {
	host, port, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		return "", "", err
	}
	out, err := exec.Command("sudo", "-n", "/sbin/pfctl", "-s", "state").Output()
	if err != nil {
		return "", "", err
	}
	remoteAddr, remotePort, err := translatePfctlOutput(host, port, string(out))
	if err != nil {
		return "", "", err
	}
	return remoteAddr, remotePort, err
}

func translatePfctlOutput(address string, port, s string) (string, string, error) {
	// We may get an ipv4-mapped ipv6 address here, e.g. ::ffff:127.0.0.1.
	// Those still appear as "127.0.0.1" in the table, so we need to strip the prefix.
	// re := regexp.MustCompile(`^::ffff:((\d+\.\d+\.\d+\.\d+$))`)
	// strippedAddress := re.ReplaceAllString(address, "")
	strippedAddress := address

	// ALL tcp 192.168.1.13:57474 -> 23.205.82.58:443       ESTABLISHED:ESTABLISHED
	spec := net.JoinHostPort(strippedAddress, port)

	lines := strings.Split(s, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED:ESTABLISHED") {
			if strings.Contains(line, spec) {
				fields := strings.Fields(line)
				if len(fields) > 4 {
					return net.SplitHostPort(fields[4])
				}
			}
		}
	}

	return "", "", fmt.Errorf("could not resolve original destination")
}
