package udp

import (
	"context"
	"math"
	"net"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
)

const (
	MaxMessageSize = math.MaxUint16
)

type Relay struct {
	pc1 net.PacketConn
	pc2 net.PacketConn

	bypass bypass.Bypass
	logger logger.Logger
}

func NewRelay(pc1, pc2 net.PacketConn) *Relay {
	return &Relay{
		pc1: pc1,
		pc2: pc2,
	}
}

func (r *Relay) WithBypass(bp bypass.Bypass) *Relay {
	r.bypass = bp
	return r
}

func (r *Relay) WithLogger(logger logger.Logger) *Relay {
	r.logger = logger
	return r
}

func (r *Relay) Run(ctx context.Context) (err error) {
	errc := make(chan error, 2)

	go func() {
		var b [MaxMessageSize]byte
		for {
			err := func() error {
				n, raddr, err := r.pc1.ReadFrom(b[:])
				if err != nil {
					return err
				}

				if r.bypass != nil && r.bypass.Contains(ctx, "udp", raddr.String()) {
					if r.logger != nil {
						r.logger.Warn("bypass: ", raddr)
					}
					return nil
				}

				if _, err := r.pc2.WriteTo(b[:n], raddr); err != nil {
					return err
				}

				if r.logger != nil {
					r.logger.Tracef("%s >>> %s data: %d",
						r.pc2.LocalAddr(), raddr, n)

				}

				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		var b [MaxMessageSize]byte
		for {
			err := func() error {
				n, raddr, err := r.pc2.ReadFrom(b[:])
				if err != nil {
					return err
				}

				if r.bypass != nil && r.bypass.Contains(ctx, "udp", raddr.String()) {
					if r.logger != nil {
						r.logger.Warn("bypass: ", raddr)
					}
					return nil
				}

				if _, err := r.pc1.WriteTo(b[:n], raddr); err != nil {
					return err
				}

				if r.logger != nil {
					r.logger.Tracef("%s <<< %s data: %d",
						r.pc2.LocalAddr(), raddr, n)

				}

				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
}
