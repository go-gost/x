package redirect

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func (h *redirectHandler) getOriginalDstAddr(conn net.Conn) (addr net.Addr, err error) {
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		err = errors.New("wrong connection type, must be TCP Conn")
		return
	}

	sc, ok := conn.(syscall.Conn)
	if !ok {
		err = errors.New("wrong connection type, must be syscall.Conn")
		return
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}

	var cerr error
	err = rc.Control(func(fd uintptr) {
		if tcpAddr.IP.To4() != nil {
			// SO_ORIGINAL_DST returns a struct sockaddr_in (16 bytes).
			// GetsockoptIPv6Mreq reads into a 20-byte ipv6_mreq; only the
			// first 16 bytes (the Multiaddr field) are populated.
			// Layout: [0:2]=sin_family, [2:4]=sin_port (BE), [4:8]=sin_addr.
			mreq, err := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, unix.SO_ORIGINAL_DST)
			if err != nil {
				cerr = err
				return
			}

			addr = &net.TCPAddr{
				IP:   net.IP(mreq.Multiaddr[4:8]),
				Port: int(mreq.Multiaddr[2])<<8 + int(mreq.Multiaddr[3]),
			}
		} else {
			// SO_ORIGINAL_DST returns a struct sockaddr_in6 (28 bytes).
			// GetsockoptIPv6MTUInfo reads into a 32-byte ipv6_mtuinfo; only
			// the first 28 bytes (the Addr field) are populated.
			info, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.IPPROTO_IPV6, unix.SO_ORIGINAL_DST)
			if err != nil {
				cerr = err
				return
			}

			// info.Addr.Port is in network byte order (big-endian).
			addr = &net.TCPAddr{
				IP:   net.IP(info.Addr.Addr[:]),
				Port: int(uint16(info.Addr.Port>>8 | info.Addr.Port<<8)),
			}
		}
	})
	if err != nil {
		return
	}
	if cerr != nil {
		return nil, cerr
	}

	return
}
