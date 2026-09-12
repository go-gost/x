// Package streamconn adapts a gRPC bidirectional Tunnel byte stream (the p2p
// plugin's data plane) to a net.Conn for the GOST side. The p2p host keeps its
// own minimal raw conn (p2p/streamconn.go) instead of sharing this one: the
// plugin module holds contracts only, and the host cannot import the x module.
// The two sides couple through the proto (Chunk messages), not through code.
//
// Two modes:
//   - raw ("tcp"): Read/Write move the stream's bytes; writes are split into
//     chunks below gRPC's default message limit.
//   - framed ("udp"): Read returns exactly one length-prefixed datagram and
//     Write sends one, preserving datagram boundaries through the byte stream
//     (the same 2-byte BE prefix the p2p datagram channel uses — the framing
//     helpers below are the single implementation).
//
// # Backpressure
//
// A single Recv pump goroutine hands chunks to Read through a one-chunk
// channel. A stalled consumer blocks the pump, which stops calling Recv and
// lets gRPC's per-stream flow control throttle the sender — memory stays
// bounded at about two chunks.
//
// # Deadlines
//
// Read deadlines are enforced by Read itself. A write deadline must interrupt
// a Send parked in flow control, and only the client side can do that (by
// cancelling the stream), so a Conn built without an abort func (i.e. from a
// server stream) rejects write deadlines. Close never blocks: on a server
// stream it only marks the conn closed — the parked Recv unblocks when the
// handler returns, which ends the RPC and cancels the stream (grpc-go
// finishStream calls the stream's cancel for exactly this reason).
package streamconn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
)

// Stream is the data-carrying half of the P2P Tunnel RPC; it is satisfied by
// both proto.P2P_TunnelClient and proto.P2P_TunnelServer.
type Stream interface {
	Send(*proto.Chunk) error
	Recv() (*proto.Chunk, error)
	Context() context.Context
}

// writeChunkSize bounds one Send; it stays well under gRPC's 4 MiB default
// receive limit.
const writeChunkSize = 32 * 1024

// MaxFrame is the largest payload that fits the 2-byte length prefix.
const MaxFrame = 65535

// WriteFrame writes p as one length-prefixed frame.
func WriteFrame(w io.Writer, p []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	bufs := net.Buffers{hdr[:], p}
	_, err := bufs.WriteTo(w)
	return err
}

// ReadFrame reads one length-prefixed frame. A zero-length frame returns
// (nil, nil); the caller should skip it.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, nil
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

var _ net.Conn = (*Conn)(nil)

// Conn is a net.Conn over a Stream. abort, when non-nil, cancels the
// underlying stream (the client side's context.CancelFunc); the host side
// passes nil because a server handler cannot abort its stream.
func New(s Stream, abort func(), network string, local, remote net.Addr) *Conn {
	c := &Conn{
		s:      s,
		abort:  abort,
		framed: network == "udp",
		local:  local,
		remote: remote,
		chunks: make(chan *proto.Chunk, 1),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		rdWake: make(chan struct{}),
	}
	go c.pump()
	return c
}

type Conn struct {
	s             Stream
	abort         func()
	framed        bool
	local, remote net.Addr

	chunks chan *proto.Chunk // cap 1: the pump blocks here when the consumer is behind
	done   chan struct{}     // closed by the pump when Recv ends
	closed chan struct{}     // closed by Close
	rdWake chan struct{}     // closed and replaced by SetReadDeadline to wake parked Reads

	closeOnce sync.Once
	sendMu    sync.Mutex // serializes Send (gRPC allows one sender)

	mu     sync.Mutex // guards err, rb, rd, wd
	err    error      // Recv's terminal error
	rb     []byte     // chunk bytes not yet consumed by Read
	rd, wd time.Time
}

// pump moves chunks from Recv to Read. It blocks on the one-chunk handoff, so
// Recv is never called while a chunk is unconsumed — that is the backpressure.
// Every exit path funnels through run's return value: the terminal error is
// stored and done closed, so a reader parked in Read always wakes. That
// matters most when the transport dies under a server-side pump (the client
// aborts the stream): nothing else would ever wake the host's pipe, hanging
// the handler and leaking the record.
func (c *Conn) pump() {
	err := c.run()
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *Conn) run() error {
	for {
		chunk, err := c.s.Recv()
		if err != nil {
			return err
		}
		select {
		case c.chunks <- chunk:
		case <-c.closed:
			return net.ErrClosed
		case <-c.s.Context().Done():
			// The stream died (client abort/RST on a server stream, or a
			// canceled client context).
			return c.s.Context().Err()
		}
	}
}

// nextChunk returns the next chunk payload, honoring closed, the pump's
// terminal state, and the read deadline. A deadline set while parked wakes
// the select (rdWake) and re-evaluates; a chunk delivered before the terminal
// state is returned first, the error on the following call — otherwise a
// random select could drop the last chunk of a clean EOF (silent truncation).
func (c *Conn) nextChunk() ([]byte, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}

	for {
		c.mu.Lock()
		dl := c.rd
		wake := c.rdWake
		c.mu.Unlock()

		var tch <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			tch = timer.C
		}

		select {
		case chunk := <-c.chunks:
			if timer != nil {
				timer.Stop()
			}
			return chunk.GetData(), nil
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return nil, net.ErrClosed
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			select {
			case chunk := <-c.chunks:
				return chunk.GetData(), nil
			default:
			}
			return nil, c.termErr()
		case <-tch:
			return nil, os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
			// The read deadline changed while parked: re-evaluate it.
		}
	}
}

func (c *Conn) termErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.framed {
		p, err := c.readDatagram()
		if err != nil {
			return 0, err
		}
		// Datagram semantics: bytes beyond b are discarded, as on a UDP socket.
		return copy(b, p), nil
	}
	for {
		c.mu.Lock()
		if len(c.rb) > 0 {
			n := copy(b, c.rb)
			c.rb = c.rb[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		data, err := c.nextChunk()
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		c.rb = data
		c.mu.Unlock()
	}
}

// readDatagram assembles one complete frame across chunks. c.rb only ever
// accumulates up to MaxFrame+one chunk: a frame header bounds the wait.
func (c *Conn) readDatagram() ([]byte, error) {
	for {
		c.mu.Lock()
		rb := c.rb
		if len(rb) >= 2 {
			n := int(binary.BigEndian.Uint16(rb))
			if len(rb) >= 2+n {
				p := rb[2 : 2+n]
				c.rb = c.rb[2+n:]
				c.mu.Unlock()
				return p, nil
			}
		}
		c.mu.Unlock()

		data, err := c.nextChunk()
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.rb = append(c.rb, data...)
		c.mu.Unlock()
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	if c.framed {
		if len(b) > MaxFrame {
			return 0, errors.New("streamconn: datagram exceeds MaxFrame")
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, b); err != nil {
			return 0, err
		}
		if err := c.send(buf.Bytes()); err != nil {
			return 0, err
		}
		return len(b), nil // datagram: the payload length, not the frame
	}

	if err := c.send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) send(b []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	for len(b) > 0 {
		n := min(len(b), writeChunkSize)
		if err := c.sendChunk(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (c *Conn) sendChunk(p []byte) error {
	// A write deadline parks the Send in flow control; only a stream cancel
	// unblocks it, so the watchdog requires an abort func.
	if c.abort != nil {
		if dl := c.writeDeadline(); !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return os.ErrDeadlineExceeded
			}
			t := time.AfterFunc(d, c.abort)
			defer t.Stop()
		}
	}
	return c.s.Send(&proto.Chunk{Data: p})
}

// Close marks the conn closed and aborts the stream when possible. It is
// idempotent and never blocks on the pump.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		if c.err == nil {
			c.err = net.ErrClosed
		}
		c.mu.Unlock()
		close(c.closed)
		if c.abort != nil {
			c.abort()
		}
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	close(c.rdWake) // interrupt a parked Read; net.Conn deadlines apply to in-flight reads
	c.rdWake = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.abort == nil {
		return &net.OpError{Op: "set", Net: "p2p", Err: errors.New("write deadline not supported on a server stream")}
	}
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	return nil
}

func (c *Conn) writeDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wd
}
