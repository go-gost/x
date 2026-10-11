package redirect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	xlogger "github.com/go-gost/x/logger"
	mdata "github.com/go-gost/x/metadata"
)

// errStubDial is the error the stub router returns for every dial, so the
// handler can be asserted to have reached the forwarding stage.
var errStubDial = errors.New("dial failed")

// recordingRouter fails every dial but records the hosts it was asked to
// dial, so a test can assert which destination the handler forwarded to. The
// port is ignored: in tproxy test mode dstAddr's port is the listener's own
// ephemeral port, so only the host carries the sniffed SNI signal.
type recordingRouter struct {
	hosts []string
}

func (r *recordingRouter) Options() *chain.RouterOptions { return nil }
func (r *recordingRouter) Dial(_ context.Context, _ string, addr string, _ ...chain.DialOption) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	r.hosts = append(r.hosts, host)
	return nil, errStubDial
}
func (r *recordingRouter) Bind(context.Context, string, string, ...chain.BindOption) (net.Listener, error) {
	return nil, errors.New("bind failed")
}

// tlsClientHello builds a TLS ClientHello record carrying SNI `name`, enough
// for Sniff to classify the stream as TLS and ParseClientHello to extract it.
func tlsClientHello(t *testing.T, name string) []byte {
	t.Helper()
	msg := &dissector.ClientHelloMsg{
		Version:            dissector.VersionTLS12,
		CipherSuites:       []uint16{0x002f}, // TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethods: []uint8{0},
		Extensions: []dissector.Extension{
			&dissector.ServerNameExtension{NameType: 0, Name: name},
		},
	}
	handshake, err := msg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rec := &dissector.Record{
		Type:    dissector.Handshake,
		Version: dissector.VersionTLS12,
		Opaque:  handshake,
	}
	var buf bytes.Buffer
	if _, err := rec.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dialRouter ignores the requested address and dials target instead, so a test
// can stand up a real backend and assert the bytes that reach it.
type dialRouter struct {
	target string
}

func (r *dialRouter) Options() *chain.RouterOptions { return nil }
func (r *dialRouter) Dial(ctx context.Context, network, _ string, _ ...chain.DialOption) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, r.target)
}
func (r *dialRouter) Bind(context.Context, string, string, ...chain.BindOption) (net.Listener, error) {
	return nil, errors.New("bind failed")
}

// gost#913: an unhandled protocol must not only reach the backend, it must
// arrive intact — the sniffed-but-unread bytes have to be replayed through
// io.MultiReader ahead of the rest of the stream.
func TestHandler_UnhandledProtoPayloadReplayedIntact(t *testing.T) {
	// Backend that reads a fixed number of bytes and echoes a reply, standing
	// in for a server-speaks-first protocol such as SMTP.
	const reply = "hello from destination\r\n"
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 14)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				c.Write([]byte(reply))
			}(c)
		}
	}()

	h := NewHandler(
		handler.RouterOption(&dialRouter{target: backend.Addr().String()}),
		handler.LoggerOption(xlogger.NewLogger()),
	)
	if err := h.Init(mdata.NewMetadata(map[string]any{
		"tproxy":   true,
		"sniffing": true,
	})); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	server := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			server <- c
		}
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn := <-server
	defer conn.Close()
	go h.Handle(context.Background(), conn)

	// The client speaks first, with a greeting the sniffer classifies as ssh.
	const greeting = "SSH-2.0-gost\r\n"
	if _, err := client.Write([]byte(greeting)); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(reply))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("backend never replied, the greeting was not forwarded: %v", err)
	}
	if string(buf) != reply {
		t.Fatalf("got %q, want %q", buf, reply)
	}
}

// gost#891 / gost#913: sniffing.fallback governs only what happens after
// HTTP/TLS handling fails. A ClientHello that Sniff classifies as TLS but
// ParseClientHello rejects must be dropped when fallback is off, and replayed
// verbatim to the backend when it is on — the bytes the sniffer consumed must
// not be lost in either case.
func TestHandler_TLSHandlingFailureRespectsFallback(t *testing.T) {
	// TLS record header (handshake, TLS 1.0) followed by a payload that is not
	// a parsable ClientHello.
	badHello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x05}, []byte("junkjunk")...)

	t.Run("fallback off", func(t *testing.T) {
		router := &recordingRouter{}
		h := NewHandler(
			handler.RouterOption(router),
			handler.LoggerOption(xlogger.NewLogger()),
		)
		if err := h.Init(mdata.NewMetadata(map[string]any{
			"tproxy":            true,
			"sniffing":          true,
			"sniffing.fallback": false,
		})); err != nil {
			t.Fatal(err)
		}

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		server := make(chan net.Conn, 1)
		go func() {
			if c, err := l.Accept(); err == nil {
				server <- c
			}
		}()

		client, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		conn := <-server
		defer conn.Close()

		if _, err := client.Write(badHello); err != nil {
			t.Fatal(err)
		}

		if err := h.Handle(context.Background(), conn); err == nil {
			t.Fatal("got nil error, want the sniffer's parse failure")
		}
		if len(router.hosts) != 0 {
			t.Fatalf("failed TLS handling fell back to raw forwarding: %v", router.hosts)
		}
	})

	t.Run("fallback on", func(t *testing.T) {
		// Backend echoes back exactly what it received.
		backend, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		go func() {
			for {
				c, err := backend.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					io.Copy(c, c)
				}(c)
			}
		}()

		h := NewHandler(
			handler.RouterOption(&dialRouter{target: backend.Addr().String()}),
			handler.LoggerOption(xlogger.NewLogger()),
		)
		if err := h.Init(mdata.NewMetadata(map[string]any{
			"tproxy":            true,
			"sniffing":          true,
			"sniffing.fallback": true,
		})); err != nil {
			t.Fatal(err)
		}

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		server := make(chan net.Conn, 1)
		go func() {
			if c, err := l.Accept(); err == nil {
				server <- c
			}
		}()

		client, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		conn := <-server
		defer conn.Close()
		go h.Handle(context.Background(), conn)

		if _, err := client.Write(badHello); err != nil {
			t.Fatal(err)
		}
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(badHello))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatalf("fallback did not forward to the backend: %v", err)
		}
		if !bytes.Equal(buf, badHello) {
			t.Fatalf("backend got %x, want %x", buf, badHello)
		}
	})
}

// gost#899: a whitelist bypass containing only domains must not reject the
// destination IP before sniffing runs. The sniffer matches the SNI host, so a
// whitelisted domain (example.com) is forwarded even though its bare IP is
// never in the whitelist.
func TestHandler_WhitelistDomainForwarded(t *testing.T) {
	bp := xbypass.NewBypass(
		xbypass.WhitelistOption(true),
		xbypass.MatchersOption([]string{"example.com"}),
		xbypass.LoggerOption(xlogger.Nop()),
	)

	router := &recordingRouter{}
	h := NewHandler(
		handler.RouterOption(router),
		handler.BypassOption(xbypass.BypassGroup(bp)),
		handler.LoggerOption(xlogger.NewLogger()),
	)
	if err := h.Init(mdata.NewMetadata(map[string]any{
		"tproxy":            true, // destination = conn.LocalAddr
		"sniffing":          true,
		"sniffing.fallback": true,
	})); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	server := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			server <- c
		}
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn := <-server
	defer conn.Close()

	if _, err := client.Write(tlsClientHello(t, "example.com")); err != nil {
		t.Fatal(err)
	}

	// The handler must reach the sniffer's dial stage (pre-check skipped) and
	// dial the sniffed host. The stub router fails the dial, but only after
	// recording the host, which is the assertion that matters.
	h.Handle(context.Background(), conn)

	if !slices.Contains(router.hosts, "example.com") {
		t.Fatalf("handler did not dial the sniffed host; hosts = %v", router.hosts)
	}
}

// gost#913: a protocol the sniffer does not classify must fall through to raw
// forwarding to the original dstAddr, exactly as it did before 3.3.0, no matter
// what sniffing.fallback is set to. sniffing.fallback only governs what happens
// after HTTP/TLS handling fails.
func TestHandler_UnhandledProtoFallsThroughToRawForwarding(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"ssh", []byte("SSH-2.0-gost\r\n")},
		{"redis", []byte("*1\r\n$4\r\nPING\r\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &recordingRouter{}
			h := NewHandler(
				handler.RouterOption(router),
				handler.LoggerOption(xlogger.NewLogger()),
			)
			// sniffing.fallback is deliberately left off (the default).
			if err := h.Init(mdata.NewMetadata(map[string]any{
				"tproxy":   true,
				"sniffing": true,
			})); err != nil {
				t.Fatal(err)
			}

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			server := make(chan net.Conn, 1)
			go func() {
				if c, err := l.Accept(); err == nil {
					server <- c
				}
			}()

			client, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			conn := <-server
			defer conn.Close()

			if _, err := client.Write(tt.payload); err != nil {
				t.Fatal(err)
			}

			// The stub router fails the dial, but only after recording the
			// address, so a non-empty hosts list proves the handler reached
			// the raw forwarding stage instead of closing the connection.
			h.Handle(context.Background(), conn)

			if len(router.hosts) == 0 {
				t.Fatalf("unhandled protocol %q was not forwarded to the original dstAddr", tt.name)
			}
		})
	}
}

// gost#913: when the client sends nothing within sniffing.timeout, Sniff
// returns an empty proto. That is also "not handled by the sniffer" and must
// reach raw forwarding rather than closing the connection.
func TestHandler_SniffTimeoutFallsThroughToRawForwarding(t *testing.T) {
	router := &recordingRouter{}
	h := NewHandler(
		handler.RouterOption(router),
		handler.LoggerOption(xlogger.NewLogger()),
	)
	if err := h.Init(mdata.NewMetadata(map[string]any{
		"tproxy":            true,
		"sniffing":          true,
		"sniffing.timeout":  "100ms",
		"sniffing.fallback": false,
	})); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	server := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			server <- c
		}
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn := <-server
	defer conn.Close()

	// The client stays silent, so the sniffing read deadline expires.
	h.Handle(context.Background(), conn)

	if len(router.hosts) == 0 {
		t.Fatal("connection with no sniffed protocol was not forwarded to the original dstAddr")
	}
}

// gost#899 (security): a non-whitelisted host must still be rejected, so the
// pre-sniffing skip does not let arbitrary traffic through in whitelist mode.
func TestHandler_WhitelistRejectsNonWhitelistedHost(t *testing.T) {
	bp := xbypass.NewBypass(
		xbypass.WhitelistOption(true),
		xbypass.MatchersOption([]string{"example.com"}),
		xbypass.LoggerOption(xlogger.Nop()),
	)

	router := &recordingRouter{}
	h := NewHandler(
		handler.RouterOption(router),
		handler.BypassOption(xbypass.BypassGroup(bp)),
		handler.LoggerOption(xlogger.NewLogger()),
	)
	if err := h.Init(mdata.NewMetadata(map[string]any{
		"tproxy":            true,
		"sniffing":          true,
		"sniffing.fallback": true,
	})); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	server := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			server <- c
		}
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn := <-server
	defer conn.Close()

	if _, err := client.Write(tlsClientHello(t, "google.com")); err != nil {
		t.Fatal(err)
	}

	err = h.Handle(context.Background(), conn)
	if !errors.Is(err, xbypass.ErrBypass) {
		t.Fatalf("got %v, want ErrBypass", err)
	}
	if len(router.hosts) != 0 {
		t.Fatalf("non-whitelisted host was dialed: %v", router.hosts)
	}
}
