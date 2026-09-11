package udp

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
)

const (
	defaultBufferSize = 4096
)

// Relay copies UDP datagrams between two net.PacketConns bidirectionally.
type Relay struct {
	service     string
	pc1         net.PacketConn
	pc2         net.PacketConn
	bufferSize  int
	readTimeout time.Duration
	bypass      bypass.Bypass
	logger      logger.Logger
}

// NewRelay creates a Relay that copies datagrams between pc1 and pc2.
func NewRelay(pc1, pc2 net.PacketConn) *Relay {
	return &Relay{
		pc1: pc1,
		pc2: pc2,
	}
}

// WithService sets the service name for bypass matching.
func (r *Relay) WithService(service string) *Relay {
	r.service = service
	return r
}

// WithBypass sets the bypass matcher to skip certain addresses.
func (r *Relay) WithBypass(bp bypass.Bypass) *Relay {
	r.bypass = bp
	return r
}

// WithLogger sets the logger.
func (r *Relay) WithLogger(logger logger.Logger) *Relay {
	r.logger = logger
	return r
}

// WithBufferSize sets the buffer size for copy operations.
func (r *Relay) WithBufferSize(n int) *Relay {
	r.bufferSize = n
	return r
}

// WithReadTimeout sets an idle read timeout for both relay directions. When a
// read blocks for longer than d the relay terminates and closes both packet
// conns. A value of 0 disables the timeout, relying on ctx cancellation to
// detect dead associations.
func (r *Relay) WithReadTimeout(d time.Duration) *Relay {
	r.readTimeout = d
	return r
}

// Run starts the relay. It blocks until an error occurs or ctx is cancelled.
// Both packet conns are closed before returning so the underlying sockets are
// released and the pending read in either direction is unblocked.
func (r *Relay) Run(ctx context.Context) (err error) {
	errc := make(chan error, 2)

	bufferSize := r.bufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	go func() {
		b := bufpool.Get(bufferSize)
		defer bufpool.Put(b)

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			default:
			}

			err := func() error {
				if r.readTimeout > 0 {
					if rd, ok := r.pc1.(interface{ SetReadDeadline(time.Time) error }); ok {
						rd.SetReadDeadline(time.Now().Add(r.readTimeout))
					}
				}

				n, raddr, err := r.pc1.ReadFrom(b)
				if err != nil {
					return err
				}

				if r.bypass != nil && r.bypass.Contains(ctx, "udp", raddr.String(), bypass.WithService(r.service)) {
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
		b := bufpool.Get(bufferSize)
		defer bufpool.Put(b)

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			default:
			}

			err := func() error {
				if r.readTimeout > 0 {
					if rd, ok := r.pc2.(interface{ SetReadDeadline(time.Time) error }); ok {
						rd.SetReadDeadline(time.Now().Add(r.readTimeout))
					}
				}

				n, raddr, err := r.pc2.ReadFrom(b)
				if err != nil {
					return err
				}

				if r.bypass != nil && r.bypass.Contains(ctx, "udp", raddr.String(), bypass.WithService(r.service)) {
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

	select {
	case err = <-errc:
	case <-ctx.Done():
		err = ctx.Err()
	}

	// Release the packet conns and unblock the remaining copy goroutine.
	r.pc1.Close()
	r.pc2.Close()

	return
}
