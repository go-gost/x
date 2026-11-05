package tun

import (
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// Link policy. These are vars rather than consts so a test can shrink a
// timeout without waiting half a minute for a verdict.
var (
	meshQueueDepth          = 256
	meshFirstInboundTimeout = 30 * time.Second
	meshInboundTimeout      = 30 * time.Second
	meshRegisterInterval    = 10 * time.Second
	meshIdleTimeout         = 5 * time.Minute
	meshWriteTimeout        = 30 * time.Second
	meshWatchdogInterval    = time.Second
)

// meshLink is one p2p datagram stream: a hub link or an on-demand direct link.
//
// Writes are queued and performed by one goroutine, so the device reader never
// blocks on a peer that stopped reading. The queue is bounded; overflow is the
// caller's signal to fall back to the hub or drop. The link also owns its
// keepalive and liveness checks: a stream can outlive the session under it, so
// silence is the only signal that the far side stopped serving this link.
type meshLink struct {
	key           string
	conn          net.Conn
	dialedLocally bool
	hub           bool

	send chan []byte
	done chan struct{}

	closeOnce sync.Once
	wmu       sync.Mutex

	ready       atomic.Bool
	since       time.Time
	lastInbound atomic.Int64 // unix nanos
	lastTraffic atomic.Int64 // unix nanos
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64

	onClose func(*meshLink, MeshCloseReason)
}

func newMeshLink(key string, conn net.Conn, dialedLocally, hub bool, onClose func(*meshLink, MeshCloseReason)) *meshLink {
	now := time.Now()
	l := &meshLink{
		key:           key,
		conn:          conn,
		dialedLocally: dialedLocally,
		hub:           hub,
		send:          make(chan []byte, meshQueueDepth),
		done:          make(chan struct{}),
		since:         now,
		onClose:       onClose,
	}
	l.lastTraffic.Store(now.UnixNano())
	return l
}

// enqueue copies pkt and hands it to the writer without blocking. It returns
// false when the queue is full or the link is closed; the caller decides
// whether to fall back to the hub or drop.
func (l *meshLink) enqueue(pkt []byte) bool {
	select {
	case <-l.done:
		return false
	default:
	}

	cp := append([]byte(nil), pkt...)
	select {
	case l.send <- cp:
		l.lastTraffic.Store(time.Now().UnixNano())
		return true
	case <-l.done:
		return false
	default:
		return false
	}
}

// markInbound records that the peer spoke on this link. Any inbound frame is
// proof the stream is alive; the registration echo is only the steady source.
func (l *meshLink) markInbound() {
	now := time.Now()
	l.ready.Store(true)
	l.lastInbound.Store(now.UnixNano())
	l.lastTraffic.Store(now.UnixNano())
}

// close ends the link exactly once and reports why. The callback runs outside
// the link's write lock and after done is closed, so it can remove the link
// from the handler without deadlocking the reader that noticed the end.
func (l *meshLink) close(reason MeshCloseReason) {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.conn.Close()
		if l.onClose != nil {
			l.onClose(l, reason)
		}
	})
}

// start launches the link's goroutines. first is an already-read frame (the
// first frame of an inbound stream); registration is sent immediately and then
// every meshRegisterInterval. A nil registration disables the sender.
func (l *meshLink) start(first []byte, registration []byte, onFrame func([]byte) error) {
	go l.writeLoop()
	go l.readLoop(first, onFrame)
	if len(registration) > 0 {
		go l.keepaliveLoop(registration)
	}
	go l.watchdog()
}

func (l *meshLink) writeLoop() {
	defer l.recoverPanic("write")
	for {
		select {
		case <-l.done:
			return
		case pkt := <-l.send:
			if err := l.writeFrame(pkt); err != nil {
				l.close(MeshCloseWrite)
				return
			}
		}
	}
}

// recoverPanic keeps a c-shared process alive: the tun code runs inside an
// Android app, where an unrecovered goroutine panic aborts the whole process.
var (
	meshLinkPanicLog = func(where, peer string, r any) {
		slog.Error("tun mesh link panic",
			"where", where,
			"peer", peer,
			"panic", r,
			"stack", string(debug.Stack()),
		)
	}
	meshDevicePanicLog = func(where string, r any) {
		slog.Error("tun mesh "+where+" panic",
			"panic", r,
			"stack", string(debug.Stack()),
		)
	}
)

func (l *meshLink) recoverPanic(where string) {
	if r := recover(); r != nil {
		meshLinkPanicLog(where, l.key, r)
		l.close(MeshCloseUnhealthy)
	}
}

// writeFrame serializes all writes on the link: the queue writer and the
// keepalive sender must never interleave two datagrams on one stream.
func (l *meshLink) writeFrame(pkt []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()

	_ = l.conn.SetWriteDeadline(time.Now().Add(meshWriteTimeout))
	n, err := l.conn.Write(pkt)
	if n > 0 {
		l.bytesOut.Add(uint64(n))
		l.lastTraffic.Store(time.Now().UnixNano())
	}
	return err
}

func (l *meshLink) readLoop(first []byte, onFrame func([]byte) error) {
	defer l.recoverPanic("read")
	if len(first) > 0 {
		l.bytesIn.Add(uint64(len(first)))
		l.markInbound()
		if err := l.handleFrame(first, onFrame); err != nil {
			l.close(MeshCloseRemote)
			return
		}
	}

	buf := make([]byte, MaxMessageSize)
	for {
		n, err := l.conn.Read(buf)
		if n > 0 {
			l.bytesIn.Add(uint64(n))
			l.markInbound()
			if err := l.handleFrame(buf[:n], onFrame); err != nil {
				l.close(MeshCloseRemote)
				return
			}
		}
		if err != nil {
			l.close(MeshCloseRemote)
			return
		}
		if n == 0 {
			continue
		}
	}
}

func (l *meshLink) handleFrame(pkt []byte, onFrame func([]byte) error) error {
	if onFrame == nil {
		return net.ErrClosed
	}
	return onFrame(pkt)
}

func (l *meshLink) keepaliveLoop(registration []byte) {
	defer l.recoverPanic("keepalive")
	ticker := time.NewTicker(meshRegisterInterval)
	defer ticker.Stop()

	for {
		if err := l.writeFrame(registration); err != nil {
			l.close(MeshCloseWrite)
			return
		}
		select {
		case <-ticker.C:
		case <-l.done:
			return
		}
	}
}

func (l *meshLink) watchdog() {
	defer l.recoverPanic("watchdog")
	ticker := time.NewTicker(meshWatchdogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			if !l.ready.Load() {
				if now.Sub(l.since) > meshFirstInboundTimeout {
					l.close(MeshCloseDial)
					return
				}
				continue
			}
			last := l.lastInbound.Load()
			if last > 0 && now.Sub(time.Unix(0, last)) > meshInboundTimeout {
				l.close(MeshCloseUnhealthy)
				return
			}
			if !l.hub {
				traffic := l.lastTraffic.Load()
				if traffic > 0 && now.Sub(time.Unix(0, traffic)) > meshIdleTimeout {
					l.close(MeshCloseIdle)
					return
				}
			}
		case <-l.done:
			return
		}
	}
}
