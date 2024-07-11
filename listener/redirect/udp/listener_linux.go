package udp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/go-gost/core/common/bufpool"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// https://github.com/KatelynHaworth/go-tproxy
func (l *redirectListener) listenUDP(addr string) (*net.UDPConn, error) {
	/*
		laddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
	*/

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					l.logger.Errorf("SetsockoptInt(SOL_IP, IP_TRANSPARENT, 1): %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
					l.logger.Errorf("SetsockoptInt(SOL_IP, IP_RECVORIGDSTADDR, 1): %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
					l.logger.Errorf("SetsockoptInt(SOL_IPV6, IPV6_TRANSPARENT, 1): %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
					l.logger.Errorf("SetsockoptInt(SOL_IPV6, IPV6_RECVORIGDSTADDR, 1): %v", err)
				}
			})
		},
	}

	network := "udp"
	if xnet.IsIPv4(addr) {
		network = "udp4"
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}

	return pc.(*net.UDPConn), nil
}

func (l *redirectListener) accept() (conn net.Conn, err error) {
	b := bufpool.Get(l.md.readBufferSize)

	n, raddr, dstAddr, err := readFromUDP(l.ln, b)
	if err != nil {
		l.logger.Error(err)
		return
	}

	l.logger.Infof("%s >> %s", raddr.String(), dstAddr.String())

	if l.options.Netns != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originNs, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("netns.Get(): %v", err)
		}
		defer netns.Set(originNs)

		var ns netns.NsHandle

		if strings.HasPrefix(l.options.Netns, "/") {
			ns, err = netns.GetFromPath(l.options.Netns)
		} else {
			ns, err = netns.GetFromName(l.options.Netns)
		}
		if err != nil {
			return nil, fmt.Errorf("netns.Get(%s): %v", l.options.Netns, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("netns.Set(%s): %v", l.options.Netns, err)
		}
	}

	c, err := dialUDP("udp", dstAddr, raddr)
	if err != nil {
		l.logger.Error(err)
		return
	}

	conn = &redirConn{
		Conn: c,
		buf:  b[:n],
		ttl:  l.md.ttl,
	}
	return
}

// ReadFromUDP reads a UDP packet from c, copying the payload into b.
// It returns the number of bytes copied into b and the return address
// that was on the packet.
//
// Out-of-band data is also read in so that the original destination
// address can be identified and parsed.
func readFromUDP(conn *net.UDPConn, b []byte) (n int, remoteAddr *net.UDPAddr, dstAddr *net.UDPAddr, err error) {
	oob := bufpool.Get(8192)
	defer bufpool.Put(oob)

	n, oobn, _, remoteAddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parsing socket control message: %v", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %v", err)
			}

			pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
				Port: int(p[0])<<8 + int(p[1]),
			}
		} else if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			inet6 := &unix.RawSockaddrInet6{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, inet6); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %v", err)
			}

			p := (*[2]byte)(unsafe.Pointer(&inet6.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IP(inet6.Addr[:]),
				Port: int(p[0])<<8 + int(p[1]),
				Zone: strconv.Itoa(int(inet6.Scope_id)),
			}
		}
	}

	if dstAddr == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original destination: %v", err)
	}

	return
}

// DialUDP connects to the remote address raddr on the network net,
// which must be "udp", "udp4", or "udp6".  If laddr is not nil, it is
// used as the local address for the connection.
func dialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (net.Conn, error) {
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %v", err)}
	}

	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %v", err)}
	}

	fileDescriptor, err := unix.Socket(udpAddrFamily(network, laddr, raddr), unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %v", err)}
	}

	if laddr.IP.To4() != nil {
		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			unix.Close(fileDescriptor)
			return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %v", err)}
		}
	} else {
		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			unix.Close(fileDescriptor)
			return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IPV6_TRANSPARENT: %v", err)}
		}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %v", err)}
	}
	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEPORT: %v", err)}
	}

	if err = unix.Bind(fileDescriptor, localSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind %v: %v", laddr, err)}
	}

	if err = unix.Connect(fileDescriptor, remoteSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %v", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-dial-%v", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %v", err)}
	}

	return remoteConn, nil
}

// udpAddToSockerAddr will convert a UDPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func udpAddrToSocketAddr(addr *net.UDPAddr) (unix.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &unix.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		var err error
		var zoneID uint64
		if addr.Zone != "" {
			zoneID, err = strconv.ParseUint(addr.Zone, 10, 32)
			if err != nil {
				if itf, _ := net.InterfaceByName(addr.Zone); itf != nil {
					zoneID = uint64(itf.Index)
				}
			}
		}

		return &unix.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// udpAddrFamily will attempt to work
// out the address family based on the
// network and UDP addresses
func udpAddrFamily(net string, laddr, raddr *net.UDPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return unix.AF_INET
	case '6':
		return unix.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || raddr.IP.To4() != nil) {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
