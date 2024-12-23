package net

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func ParseInterfaceAddr(ifceName, network string) (ifce string, addr []net.Addr, err error) {
	if ifceName == "" {
		addr = append(addr, nil)
		return
	}

	ip := net.ParseIP(ifceName)
	if ip == nil {
		var ife *net.Interface
		ife, err = net.InterfaceByName(ifceName)
		if err != nil {
			return
		}
		var addrs []net.Addr
		addrs, err = ife.Addrs()
		if err != nil {
			return
		}
		if len(addrs) == 0 {
			err = fmt.Errorf("addr not found for interface %s", ifceName)
			return
		}
		ifce = ifceName
		for _, addr_ := range addrs {
			if ipNet, ok := addr_.(*net.IPNet); ok {
				addr = append(addr, ipToAddr(ipNet.IP, network))
			}
		}
	} else {
		ifce, err = findInterfaceByIP(ip)
		if err != nil {
			return
		}
		addr = []net.Addr{ipToAddr(ip, network)}
	}

	return
}

func ipToAddr(ip net.IP, network string) (addr net.Addr) {
	port := 0
	switch network {
	case "tcp", "tcp4", "tcp6":
		addr = &net.TCPAddr{IP: ip, Port: port}
		return
	case "udp", "udp4", "udp6":
		addr = &net.UDPAddr{IP: ip, Port: port}
		return
	default:
		addr = &net.IPAddr{IP: ip}
		return
	}
}

func findInterfaceByIP(ip net.IP) (string, error) {
	ifces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifce := range ifces {
		addrs, _ := ifce.Addrs()
		if len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			ipAddr, _ := addr.(*net.IPNet)
			if ipAddr == nil {
				continue
			}
			// logger.Default().Infof("%s-%s", ipAddr, ip)
			if ipAddr.IP.Equal(ip) {
				return ifce.Name, nil
			}
		}
	}
	return "", nil
}

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
		return fmt.Errorf("invalid port range: %s", s)
	}
}

func (pr *PortRange) Contains(port int) bool {
	return port >= pr.Min && port <= pr.Max
}

type IPRange struct {
	Min netip.Addr
	Max netip.Addr
}

func (r *IPRange) Parse(s string) error {
	minmax := strings.Split(s, "-")
	switch len(minmax) {
	case 1:
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return err
		}

		r.Min, r.Max = addr, addr
		return nil

	case 2:
		min, err := netip.ParseAddr(strings.TrimSpace(minmax[0]))
		if err != nil {
			return err
		}
		max, err := netip.ParseAddr(strings.TrimSpace(minmax[1]))
		if err != nil {
			return err
		}

		r.Min, r.Max = min, max
		return nil

	default:
		return fmt.Errorf("invalid ip range: %s", s)
	}
}

func (r *IPRange) Contains(addr netip.Addr) bool {
	return !(addr.Less(r.Min) || r.Max.Less(addr))
}

type ClientAddr interface {
	ClientAddr() net.Addr
}
