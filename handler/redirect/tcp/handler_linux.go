package redirect

import (
	"encoding/binary"
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
			info, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.IPPROTO_IPV6, unix.SO_ORIGINAL_DST)
			if err != nil {
				cerr = err
				return
			}

			var buf = make([]byte, 2)
			binary.BigEndian.PutUint16(buf, info.Addr.Port)
			addr = &net.TCPAddr{
				IP:   net.IP(info.Addr.Addr[:]),
				Port: int(binary.NativeEndian.Uint16(buf)),
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
