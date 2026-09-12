package redirect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"testing"

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
