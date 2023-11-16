package net

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AddrPortRange is the network address with port range supported.
// e.g. 192.168.1.1:0-65535
type AddrPortRange string

func (p AddrPortRange) Addrs() (addrs []string) {
	// ignore url scheme, e.g. http://, tls://, tcp://.
	if strings.Contains(string(p), "://") {
		return nil
	}

	h, sp, err := net.SplitHostPort(string(p))
	if err != nil {
		return nil
	}

	pr := PortRange{}
	pr.Parse(sp)

	for i := pr.Min; i <= pr.Max; i++ {
		addrs = append(addrs, net.JoinHostPort(h, strconv.Itoa(i)))
	}
	return addrs
}

// Port range is a range of port list.
type PortRange struct {
	Min int
	Max int
}

// Parse parses the s to PortRange.
// The s can be a single port number and will be converted to port range port-port.
func (pr *PortRange) Parse(s string) error {
	minmax := strings.Split(s, "-")
	switch len(minmax) {
	case 1:
		port, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if port < 0 || port > 65535 {
			return fmt.Errorf("invalid port: %s", s)
		}

		pr.Min, pr.Max = port, port
		return nil

	case 2:
		min, err := strconv.Atoi(minmax[0])
		if err != nil {
			return err
		}
		max, err := strconv.Atoi(minmax[1])
		if err != nil {
			return err
		}

		pr.Min, pr.Max = min, max
		return nil

	default:
		return fmt.Errorf("invalid range: %s", s)
	}
}

func (pr *PortRange) Contains(port int) bool {
	return port >= pr.Min && port <= pr.Max
}
