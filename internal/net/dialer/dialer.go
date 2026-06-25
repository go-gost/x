package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
)

const (
	// DefaultTimeout is the default dial timeout.
	DefaultTimeout = 10 * time.Second
)

// DefaultNetDialer is the default Dialer used when a nil Dialer is provided.
var (
	DefaultNetDialer = &Dialer{}
)

// Dialer is a network dialer with support for interface binding, network
// namespace switching, and socket marking. The zero value is ready to use
// via DefaultNetDialer.
type Dialer struct {
	Interface string
	Netns     string
	Mark      int
	DialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
	Log       logger.Logger
}

// Dial connects to addr on the named network. If d is nil, DefaultNetDialer
// is used. When Netns is set, the dial switches into that network namespace
// before creating the connection. When Interface is set, it iterates the
// specified interfaces, trying each address in turn.
func (d *Dialer) Dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if d == nil {
		d = DefaultNetDialer
	}

	log := d.Log
	if log == nil {
		log = logger.Default()
	}
	log = log.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})

	if d.Netns != "" {
		restore, err := switchNetns(d.Netns)
		if err != nil {
			return nil, err
		}
		defer restore()
	}

	if d.DialFunc != nil {
		return d.DialFunc(ctx, network, addr)
	}

	switch network {
	case "unix":
		netd := net.Dialer{}
		return netd.DialContext(ctx, network, addr)
	default:
	}

	ifces := strings.Split(d.Interface, ",")
	for _, ifce := range ifces {
		strict := strings.HasSuffix(ifce, "!")
		ifce = strings.TrimSuffix(ifce, "!")
		var ifceName string
		var ifAddrs []net.Addr
		var isIP bool
		ifceName, ifAddrs, isIP, err = xnet.ParseInterfaceAddr(ifce, network)
		if err != nil && strict {
			return
		}

		for _, ifAddr := range ifAddrs {
			conn, err = d.dialOnce(ctx, network, addr, ifceName, ifAddr, !isIP, log)
			if err == nil {
				return
			}

			log.Debugf("dial %s/%s via interface %s@%v failed: %s", addr, network, ifceName, ifAddr, err)

			if strict &&
				!strings.Contains(err.Error(), "no suitable address found") &&
				!strings.Contains(err.Error(), "mismatched local address type") {
				return
			}
		}
	}

	return
}

func (d *Dialer) dialOnce(ctx context.Context, network, addr, ifceName string, ifAddr net.Addr, bindToDevice bool, log logger.Logger) (net.Conn, error) {
	if ifceName != "" {
		log.Debugf("dial %s/%s via interface %s@%s", addr, network, ifceName, ifAddr)
	}

	switch network {
	case "udp", "udp4", "udp6":
		if addr == "" {
			var laddr *net.UDPAddr
			if ifAddr != nil {
				laddr, _ = ifAddr.(*net.UDPAddr)
			}

			c, err := net.ListenUDP(network, laddr)
			if err != nil {
				return nil, err
			}
			sc, err := c.SyscallConn()
			if err != nil {
				log.Error(err)
				return nil, err
			}
			err = sc.Control(func(fd uintptr) {
				// NOTE: bindDevice is intentionally skipped for empty-addr UDP
				// (relay/listener sockets). The ListenUDP laddr binding above
				// is sufficient to pin the source IP. SO_BINDTODEVICE would
				// force all outbound datagrams through the named interface,
				// which may conflict with the kernel routing table and cause
				// silent packet drops — breaking UDP associate (issue #287).
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("set mark: %v", err)
					}
				}
			})
			if err != nil {
				log.Error(err)
			}
			return c, nil
		}
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("dial: unsupported network %s", network)
	}
	netd := net.Dialer{
		Resolver:  &net.Resolver{PreferGo: true},
		LocalAddr: ifAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if ifceName != "" && bindToDevice {
					if err := bindDevice(network, address, fd, ifceName); err != nil {
						log.Warnf("%s/%s bind device: %v", address, network, err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("%s/%s set mark: %v", address, network, err)
					}
				}
			})
		},
	}
	if d.Netns != "" {
		// https://github.com/golang/go/issues/44922#issuecomment-796645858
		netd.FallbackDelay = -1
	}

	return netd.DialContext(ctx, network, addr)
}
