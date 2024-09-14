package dialer

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/vishvananda/netns"
)

const (
	DefaultTimeout = 10 * time.Second
)

var (
	DefaultNetDialer = &Dialer{}
)

type Dialer struct {
	Interface string
	Netns     string
	Mark      int
	DialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger    logger.Logger
}

func (d *Dialer) Dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if d == nil {
		d = DefaultNetDialer
	}

	log := d.Logger
	if log == nil {
		log = logger.Default()
	}
	log = log.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})

	if d.Netns != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originNs, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("netns.Get(): %v", err)
		}
		defer netns.Set(originNs)

		var ns netns.NsHandle
		if strings.HasPrefix(d.Netns, "/") {
			ns, err = netns.GetFromPath(d.Netns)
		} else {
			ns, err = netns.GetFromName(d.Netns)
		}
		if err != nil {
			return nil, fmt.Errorf("netns.Get(%s): %v", d.Netns, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("netns.Set(%s): %v", d.Netns, err)
		}
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
		ifceName, ifAddrs, err = xnet.ParseInterfaceAddr(ifce, network)
		if err != nil && strict {
			return
		}

		for _, ifAddr := range ifAddrs {
			conn, err = d.dialOnce(ctx, network, addr, ifceName, ifAddr, log)
			if err == nil {
				return
			}

			log.Debugf("dial %s %v@%s failed: %s", network, ifAddr, ifceName, err)

			if strict &&
				!strings.Contains(err.Error(), "no suitable address found") &&
				!strings.Contains(err.Error(), "mismatched local address type") {
				return
			}
		}
	}

	return
}

func (d *Dialer) dialOnce(ctx context.Context, network, addr, ifceName string, ifAddr net.Addr, log logger.Logger) (net.Conn, error) {
	if ifceName != "" {
		log.Debugf("interface: %s %v/%s", ifceName, ifAddr, network)
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
				if ifceName != "" {
					if err := bindDevice(fd, ifceName); err != nil {
						log.Warnf("bind device: %v", err)
					}
				}
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
		LocalAddr: ifAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if ifceName != "" {
					if err := bindDevice(fd, ifceName); err != nil {
						log.Warnf("bind device: %v", err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("set mark: %v", err)
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
