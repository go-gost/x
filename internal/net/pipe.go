package net

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/common/bufpool"
	xio "github.com/go-gost/x/internal/io"
	ws_util "github.com/go-gost/x/internal/util/ws"
)

const (
	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 10 * time.Second
)

func Pipe(ctx context.Context, rw1, rw2 io.ReadWriteCloser) error {
	wg := sync.WaitGroup{}
	wg.Add(2)

	ch := make(chan error, 2)

	go func() {
		defer wg.Done()
		if err := pipeBuffer(rw1, rw2, bufferSize/2); err != nil {
			ch <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := pipeBuffer(rw2, rw1, bufferSize/2); err != nil {
			ch <- err
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return nil
	}

	select {
	case err := <-ch:
		return err
	default:
	}

	return nil
}

func pipeBuffer(dst io.ReadWriteCloser, src io.ReadWriteCloser, bufferSize int) error {
	buf := bufpool.Get(bufferSize)
	defer bufpool.Put(buf)

	n, err := io.CopyBuffer(dst, src, buf)

	// Do the upload/download side TCP half-close.
	if cr, ok := src.(xio.CloseRead); ok {
		cr.CloseRead()
	}

	if cw, ok := dst.(xio.CloseWrite); ok {
		// WebSocket is message-based and does not support TCP half-close semantics.
		// Attempting to emulate half-close (or enforcing a half-close timeout) can
		// tear down the tunnel prematurely and manifest as abnormal websocket close
		// errors (e.g. close 1006 unexpected EOF).
		if _, isWS := dst.(ws_util.WebsocketConn); !isWS {
			if e := cw.CloseWrite(); e == xio.ErrUnsupported {
				dst.Close()
			} else {
				// Set TCP half-close timeout.
				xio.SetReadDeadline(dst, time.Now().Add(tcpWaitTimeout))
			}
		}
	} else {
		dst.Close()
	}

	if err != nil {
		return fmt.Errorf("pipe %s <- %s copied=%d: %w", connLabel(dst), connLabel(src), n, err)
	}
	return nil
}

func connLabel(v any) string {
	label := fmt.Sprintf("%T", v)
	if c, ok := v.(interface {
		LocalAddr() net.Addr
		RemoteAddr() net.Addr
	}); ok {
		la, ra := c.LocalAddr(), c.RemoteAddr()
		if la != nil || ra != nil {
			label = fmt.Sprintf("%T(%v->%v)", v, la, ra)
		}
	}
	return label
}
