package socks

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/gosocks5"
)

// slowConn is a net.Conn that pauses inside every Write before appending.
//
// A datagram frame is not written to the stream atomically:
// UDPDatagram.WriteTo issues three separate Write calls (RSV/FRAG, SOCKS5
// address, payload). Individually each Write is concurrency-safe, so when
// several per-endpoint handlers share one stream the frames can interleave
// between those calls and corrupt each other. Pausing inside Write widens the
// window so a test observes that interleaving reliably instead of rarely.
type slowConn struct {
	net.Conn
	delay time.Duration

	mu  sync.Mutex
	buf bytes.Buffer
}

func newSlowConn(d time.Duration) *slowConn { return &slowConn{delay: d} }

func (c *slowConn) Read(b []byte) (int, error) { return 0, net.ErrClosed }

func (c *slowConn) Write(b []byte) (int, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}

func (c *slowConn) Close() error { return nil }

// stream returns everything written so far, as the far end would see it.
func (c *slowConn) stream() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Test_udpTunConn_concurrentWriteTo checks that endpoints sharing one reverse
// tunnel stream cannot interleave inside a datagram frame. Same defect as
// gost#911 in the relay variant: concurrent UDP endpoints corrupted datagrams
// and left torn frames that the far end read as "unexpected EOF", rebuilding
// the whole tunnel every second.
func Test_udpTunConn_concurrentWriteTo(t *testing.T) {
	const writers = 4
	const datagramsPerWriter = 25
	const payloadLen = 1200

	conn := newSlowConn(50 * time.Microsecond)
	pc := UDPTunClientPacketConn(conn)

	addrs := make([]string, writers)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("127.0.0.1:%d", 10001+i)
	}

	payloadFor := func(id byte) []byte {
		b := make([]byte, payloadLen)
		for i := range b {
			b[i] = id
		}
		return b
	}

	var wg sync.WaitGroup
	for w := 1; w <= writers; w++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			taddr, err := net.ResolveUDPAddr("udp", addrs[int(id)-1])
			if err != nil {
				t.Errorf("resolve: %v", err)
				return
			}
			for range datagramsPerWriter {
				if _, err := pc.WriteTo(payloadFor(id), taddr); err != nil {
					t.Errorf("writer %d WriteTo: %v", id, err)
					return
				}
			}
		}(byte(w))
	}
	wg.Wait()

	// Parse the raw stream the way the far end does, one frame at a time. A
	// torn frame shows up here as a payload that does not match the address it
	// was framed with.
	stream := bytes.NewReader(conn.stream())
	total := writers * datagramsPerWriter
	for i := range total {
		socksAddr := gosocks5.Addr{}
		dgram := gosocks5.UDPDatagram{
			Header: &gosocks5.UDPHeader{Addr: &socksAddr},
		}
		if _, err := dgram.ReadFrom(stream); err != nil {
			t.Fatalf("frame %d of %d: stream corrupted by concurrent writers: %v",
				i, total, err)
		}
		id, ok := payloadID(dgram.Data)
		if !ok {
			t.Fatalf("frame %d of %d: payload is not a single-writer payload "+
				"(%d bytes), corrupted by concurrent writers", i, total, len(dgram.Data))
		}
		if got := socksAddr.String(); got != addrs[id-1] {
			t.Fatalf("frame %d of %d: payload from writer %d framed with address %s, want %s "+
				"— frames interleaved", i, total, id, got, addrs[id-1])
		}
	}
}

// payloadID recovers the writer id from a payload built by payloadFor.
func payloadID(b []byte) (byte, bool) {
	if len(b) == 0 {
		return 0, false
	}
	id := b[0]
	for _, c := range b {
		if c != id {
			return 0, false
		}
	}
	return id, true
}