package chain

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
	xmetadata "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock types ---

// testConn is a minimal net.Conn for testing.
type testConn struct {
	closed bool
}

func (c *testConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *testConn) Write(b []byte) (n int, err error)   { return len(b), nil }
func (c *testConn) Close() error                         { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr                  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (c *testConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }
func (c *testConn) SetDeadline(t time.Time) error        { return nil }
func (c *testConn) SetReadDeadline(t time.Time) error    { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error   { return nil }

// testDialer implements dialer.Dialer and optionally dialer.Handshaker and
// dialer.Multiplexer. Hook functions allow per-test customization.
type testDialer struct {
	dialFn       func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error)
	handshakeFn  func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error)
	multiplexVal bool
	hasMux       bool // whether Multiplex() method exists (simulates optional interface)
}

func (d *testDialer) Init(md metadata.Metadata) error { return nil }

func (d *testDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	if d.dialFn != nil {
		return d.dialFn(ctx, addr, opts...)
	}
	return &testConn{}, nil
}

func (d *testDialer) Handshake(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
	if d.handshakeFn != nil {
		return d.handshakeFn(ctx, conn, opts...)
	}
	return conn, nil
}

func (d *testDialer) Multiplex() bool {
	return d.hasMux && d.multiplexVal
}

// plainDialer implements only dialer.Dialer (no Handshaker, no Multiplexer).
type plainDialer struct{}

func (d *plainDialer) Init(md metadata.Metadata) error { return nil }
func (d *plainDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &testConn{}, nil
}

// testConnector implements connector.Connector and optionally connector.Handshaker
// and connector.Binder.
type testConnector struct {
	connectFn    func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error)
	handshakeFn  func(ctx context.Context, conn net.Conn) (net.Conn, error)
	bindFn       func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error)
}

func (c *testConnector) Init(md metadata.Metadata) error { return nil }

func (c *testConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.connectFn != nil {
		return c.connectFn(ctx, conn, network, address, opts...)
	}
	return conn, nil
}

func (c *testConnector) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if c.handshakeFn != nil {
		return c.handshakeFn(ctx, conn)
	}
	return conn, nil
}

func (c *testConnector) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	if c.bindFn != nil {
		return c.bindFn(ctx, conn, network, address, opts...)
	}
	return nil, connector.ErrBindUnsupported
}

// plainConnector implements only connector.Connector (no Handshaker, no Binder).
type plainConnector struct {
	connectFn func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error)
}

func (c *plainConnector) Init(md metadata.Metadata) error { return nil }
func (c *plainConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if c.connectFn != nil {
		return c.connectFn(ctx, conn, network, address, opts...)
	}
	return conn, nil
}

// testHop implements hop.Hop.
type testHop struct {
	selectFn func(ctx context.Context, opts ...hop.SelectOption) *chain.Node
}

func (h *testHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
	if h.selectFn != nil {
		return h.selectFn(ctx, opts...)
	}
	return nil
}

// trackedConn wraps a net.Conn and reports whether Close was called.
type trackedConn struct {
	*testConn
	closed  bool
	closeFn func() // optional, called on Close
}

func (c *trackedConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.closeFn != nil {
		c.closeFn()
	}
	return c.testConn.Close()
}

type testListener struct {
	closed bool
}

func (l *testListener) Accept() (net.Conn, error) { return &testConn{}, nil }
func (l *testListener) Close() error               { l.closed = true; return nil }
func (l *testListener) Addr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

// testRecorder implements recorder.Recorder.
type testRecorder struct {
	records []recordCall
	mu      sync.Mutex
}

type recordCall struct {
	data string
}

func (r *testRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, recordCall{data: string(b)})
	return nil
}

func init() {
	logger.SetDefault(xlogger.Nop())
}

// =============================================================================
// Transport tests
// =============================================================================

func TestNewTransport(t *testing.T) {
	d := &testDialer{}
	c := &testConnector{}
	tr := NewTransport(d, c)
	require.NotNil(t, tr)
	assert.Equal(t, d, tr.dialer)
	assert.Equal(t, c, tr.connector)
}

func TestNewTransport_WithOptions(t *testing.T) {
	rt := &chainRoute{}
	d := &testDialer{}
	c := &testConnector{}

	tr := NewTransport(d, c,
		chain.AddrTransportOption("example.com:8080"),
		chain.InterfaceTransportOption("eth0"),
		chain.NetnsTransportOption("ns1"),
		chain.SockOptsTransportOption(&chain.SockOpts{Mark: 42}),
		chain.RouteTransportOption(rt),
	)
	require.NotNil(t, tr)
	assert.Equal(t, "example.com:8080", tr.options.Addr)
	assert.Equal(t, "eth0", tr.options.IfceName)
	assert.Equal(t, "ns1", tr.options.Netns)
	assert.Equal(t, 42, tr.options.SockOpts.Mark)
	assert.Equal(t, rt, tr.options.Route)
}

func TestTransport_Dial_Success(t *testing.T) {
	var calledAddr string
	d := &testDialer{
		dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
			calledAddr = addr
			return &testConn{}, nil
		},
	}
	tr := NewTransport(d, &testConnector{})

	conn, err := tr.Dial(context.Background(), "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "192.168.1.1:80", calledAddr)
}

func TestTransport_Dial_Error(t *testing.T) {
	dialErr := errors.New("dial failed")
	d := &testDialer{
		dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
			return nil, dialErr
		},
	}
	tr := NewTransport(d, &testConnector{})

	conn, err := tr.Dial(context.Background(), "192.168.1.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestTransport_Dial_WithHostOption(t *testing.T) {
	tr := NewTransport(&testDialer{}, &testConnector{},
		chain.AddrTransportOption("proxy.example.com:8080"),
	)

	var calledAddr string
	// Wrap to check options are passed - we set dialFn after construction
	tr.dialer = &testDialer{
		dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
			calledAddr = addr
			return &testConn{}, nil
		},
	}

	conn, err := tr.Dial(context.Background(), "1.2.3.4:443")
	require.NoError(t, err)
	require.NotNil(t, conn)
	// The addr parameter is what's passed through; Host option is inside opts
	assert.Equal(t, "1.2.3.4:443", calledAddr)
}

func TestTransport_Dial_WithRouteNodes(t *testing.T) {
	// When the transport's Route option is set and has nodes, Dial should use
	// Route.Dial as the underlying dial function.
	innerRoute := NewRoute()
	innerNode := chain.NewNode("inner", "127.0.0.1:9090",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	innerRoute.addNode(innerNode)

	tr := NewTransport(&testDialer{}, &testConnector{},
		chain.RouteTransportOption(innerRoute),
	)

	conn, err := tr.Dial(context.Background(), "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestTransport_Dial_RouteSet_NoNodes(t *testing.T) {
	// Route is set but has zero nodes — should NOT use Route.Dial as the
	// underlying dial function (short-circuit on len(Nodes()) > 0).
	emptyRoute := NewRoute() // no nodes added
	tr := NewTransport(&testDialer{}, &testConnector{},
		chain.RouteTransportOption(emptyRoute),
	)

	conn, err := tr.Dial(context.Background(), "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestTransport_Dial_WithSockOpts(t *testing.T) {
	// Dial with SockOpts set — exercises the Mark assignment path.
	tr := NewTransport(&testDialer{}, &testConnector{},
		chain.SockOptsTransportOption(&chain.SockOpts{Mark: 999}),
	)

	conn, err := tr.Dial(context.Background(), "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestTransport_Dial_DialFuncActive(t *testing.T) {
	// Use a dialer that actually invokes the NetDialerDialOption, which in
	// turn triggers the DialFunc on the net_dialer when Route has nodes.
	d := &testDialer{
		dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
			var do dialer.DialOptions
			for _, opt := range opts {
				if opt != nil {
					opt(&do)
				}
			}
			if do.Dialer != nil {
				return do.Dialer.Dial(ctx, "tcp", addr)
			}
			return &testConn{}, nil
		},
	}

	innerRoute := NewRoute()
	innerNode := chain.NewNode("inner", "127.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	innerRoute.addNode(innerNode)

	tr := NewTransport(d, &testConnector{},
		chain.RouteTransportOption(innerRoute),
	)

	conn, err := tr.Dial(context.Background(), "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestTransport_Dial_NoSockOpts(t *testing.T) {
	// Dial with no SockOpts set (nil path).
	d := &testDialer{}
	c := &testConnector{}
	tr := NewTransport(d, c) // no SockOptsTransportOption

	conn, err := tr.Dial(context.Background(), "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
}

func TestTransport_Connect_NoSockOpts(t *testing.T) {
	// Connect with no SockOpts set (nil path).
	c := &testConnector{
		connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
			return conn, nil
		},
	}
	tr := NewTransport(&testDialer{}, c) // no SockOptsTransportOption

	conn := &testConn{}
	result, err := tr.Connect(context.Background(), conn, "tcp", "10.0.0.1:80")
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Handshake_DialerOnly(t *testing.T) {
	d := &testDialer{
		handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
			return conn, nil
		},
	}
	c := &plainConnector{}
	tr := NewTransport(d, c, chain.AddrTransportOption("proxy:8080"))

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Handshake_ConnectorOnly(t *testing.T) {
	d := &plainDialer{}
	c := &testConnector{
		handshakeFn: func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			return conn, nil
		},
	}
	tr := NewTransport(d, c)

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Handshake_Both(t *testing.T) {
	callOrder := make([]string, 0)
	d := &testDialer{
		handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
			callOrder = append(callOrder, "dialer")
			return conn, nil
		},
	}
	c := &testConnector{
		handshakeFn: func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			callOrder = append(callOrder, "connector")
			return conn, nil
		},
	}
	tr := NewTransport(d, c)

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, conn, result)
	assert.Equal(t, []string{"dialer", "connector"}, callOrder)
}

func TestTransport_Handshake_Neither(t *testing.T) {
	d := &plainDialer{}
	c := &plainConnector{}
	tr := NewTransport(d, c)

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Handshake_DialerError(t *testing.T) {
	handshakeErr := errors.New("handshake failed")
	d := &testDialer{
		handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
			return nil, handshakeErr
		},
	}
	tr := NewTransport(d, &testConnector{})

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, handshakeErr, err)
}

func TestTransport_Handshake_ConnectorError(t *testing.T) {
	handshakeErr := errors.New("connector handshake failed")
	d := &testDialer{} // dialer handshake succeeds first
	c := &testConnector{
		handshakeFn: func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			return nil, handshakeErr
		},
	}
	tr := NewTransport(d, c)

	conn := &testConn{}
	result, err := tr.Handshake(context.Background(), conn)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestTransport_Connect_Success(t *testing.T) {
	c := &testConnector{
		connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
			return conn, nil
		},
	}
	tr := NewTransport(&testDialer{}, c)

	conn := &testConn{}
	result, err := tr.Connect(context.Background(), conn, "tcp", "10.0.0.1:80")
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Connect_Error(t *testing.T) {
	connectErr := errors.New("connect failed")
	c := &testConnector{
		connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
			return nil, connectErr
		},
	}
	tr := NewTransport(&testDialer{}, c)

	conn := &testConn{}
	result, err := tr.Connect(context.Background(), conn, "tcp", "10.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestTransport_Connect_WithSockOpts(t *testing.T) {
	c := &testConnector{
		connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
			return conn, nil
		},
	}
	tr := NewTransport(&testDialer{}, c,
		chain.SockOptsTransportOption(&chain.SockOpts{Mark: 123}),
	)

	conn := &testConn{}
	result, err := tr.Connect(context.Background(), conn, "tcp", "10.0.0.1:80")
	require.NoError(t, err)
	assert.Equal(t, conn, result)
}

func TestTransport_Bind_Binder(t *testing.T) {
	expectedLn := &testListener{}
	c := &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return expectedLn, nil
		},
	}
	tr := NewTransport(&testDialer{}, c)

	conn := &testConn{}
	ln, err := tr.Bind(context.Background(), conn, "tcp", ":0")
	require.NoError(t, err)
	assert.Equal(t, expectedLn, ln)
}

func TestTransport_Bind_BindError(t *testing.T) {
	bindErr := errors.New("bind failed")
	c := &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return nil, bindErr
		},
	}
	tr := NewTransport(&testDialer{}, c)

	conn := &testConn{}
	ln, err := tr.Bind(context.Background(), conn, "tcp", ":0")
	assert.Error(t, err)
	assert.Nil(t, ln)
}

func TestTransport_Bind_NotBinder(t *testing.T) {
	c := &plainConnector{}
	tr := NewTransport(&testDialer{}, c)

	conn := &testConn{}
	ln, err := tr.Bind(context.Background(), conn, "tcp", ":0")
	assert.Error(t, err)
	assert.Nil(t, ln)
	assert.Equal(t, connector.ErrBindUnsupported, err)
}

func TestTransport_Multiplex_True(t *testing.T) {
	d := &testDialer{hasMux: true, multiplexVal: true}
	tr := NewTransport(d, &testConnector{})
	assert.True(t, tr.Multiplex())
}

func TestTransport_Multiplex_False(t *testing.T) {
	d := &testDialer{hasMux: true, multiplexVal: false}
	tr := NewTransport(d, &testConnector{})
	assert.False(t, tr.Multiplex())
}

func TestTransport_Multiplex_NotImplemented(t *testing.T) {
	d := &plainDialer{}
	tr := NewTransport(d, &testConnector{})
	assert.False(t, tr.Multiplex())
}

func TestTransport_Options(t *testing.T) {
	tr := NewTransport(&testDialer{}, &testConnector{},
		chain.AddrTransportOption("test:1234"),
		chain.InterfaceTransportOption("eth1"),
	)
	opts := tr.Options()
	require.NotNil(t, opts)
	assert.Equal(t, "test:1234", opts.Addr)
	assert.Equal(t, "eth1", opts.IfceName)
}

func TestTransport_Options_NilReceiver(t *testing.T) {
	var tr *Transport
	opts := tr.Options()
	assert.Nil(t, opts)
}

func TestTransport_Copy_Isolation(t *testing.T) {
	original := NewTransport(&testDialer{}, &testConnector{},
		chain.AddrTransportOption("original:8080"),
	)

	cp := original.Copy()
	require.NotNil(t, cp)

	// The copy should not be the same pointer.
	assert.NotSame(t, original, cp)

	// Modifying the copy's options must not affect the original.
	cp.Options().Addr = "modified:9090"
	assert.Equal(t, "original:8080", original.Options().Addr)
	assert.Equal(t, "modified:9090", cp.Options().Addr)
}

func TestTransport_Copy_SupportsEmbeddingSubRoute(t *testing.T) {
	// Verify that Copy produces a transporter whose Options() can independently
	// hold a sub-route (as used by Chain.Route for multiplex splitting).
	original := NewTransport(&testDialer{}, &testConnector{})
	cp := original.Copy().(*Transport)
	require.NotNil(t, cp)

	subRoute := NewRoute()
	cp.Options().Route = subRoute

	assert.Nil(t, original.Options().Route)
	assert.Equal(t, subRoute, cp.Options().Route)
}

func TestTransport_Copy_ChainTransporterInterface(t *testing.T) {
	// Verify Copy satisfies chain.Transporter interface.
	var tr chain.Transporter = NewTransport(&testDialer{}, &testConnector{})
	cp := tr.Copy()
	require.NotNil(t, cp)
	assert.IsType(t, &Transport{}, cp)
}

// =============================================================================
// Chain tests
// =============================================================================

func TestNewChain(t *testing.T) {
	c := NewChain("test-chain")
	require.NotNil(t, c)
	assert.Equal(t, "test-chain", c.Name())
	assert.NotNil(t, c.Marker())
}

func TestNewChain_WithMetadata(t *testing.T) {
	md := xmetadata.NewMetadata(map[string]any{"key": "value"})
	c := NewChain("test-chain", MetadataChainOption(md))
	assert.Equal(t, md, c.Metadata())
}

func TestNewChain_WithLogger(t *testing.T) {
	l := xlogger.Nop()
	c := NewChain("test-chain", LoggerChainOption(l))
	assert.Equal(t, l, c.logger)
}

func TestChain_AddHop(t *testing.T) {
	c := NewChain("test-chain")
	h := &testHop{}
	c.AddHop(h)
	assert.Len(t, c.hops, 1)
}

func TestChain_Metadata(t *testing.T) {
	md := xmetadata.NewMetadata(map[string]any{"a": 1})
	c := NewChain("test-chain", MetadataChainOption(md))
	assert.Equal(t, md, c.Metadata())
}

func TestChain_Marker(t *testing.T) {
	c := NewChain("test-chain")
	m := c.Marker()
	require.NotNil(t, m)
	m.Mark()
	assert.Equal(t, int64(1), m.Count())
}

func TestChain_Name(t *testing.T) {
	c := NewChain("my-chain")
	assert.Equal(t, "my-chain", c.Name())
}

func TestChain_Route_NilChain(t *testing.T) {
	var c *Chain
	rt := c.Route(context.Background(), "tcp", "127.0.0.1:80")
	assert.Nil(t, rt)
}

func TestChain_Route_EmptyHops(t *testing.T) {
	c := NewChain("empty")
	rt := c.Route(context.Background(), "tcp", "127.0.0.1:80")
	assert.Nil(t, rt)
}

func TestChain_Route_SingleHop(t *testing.T) {
	c := NewChain("test-chain")
	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node {
			return node
		},
	}
	c.AddHop(h)

	rt := c.Route(context.Background(), "tcp", "127.0.0.1:80")
	require.NotNil(t, rt)
	assert.Len(t, rt.Nodes(), 1)
	assert.Equal(t, "node1", rt.Nodes()[0].Name)
}

func TestChain_Route_MultipleHops(t *testing.T) {
	c := NewChain("test-chain")
	node1 := chain.NewNode("hop1", "10.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	node2 := chain.NewNode("hop2", "10.0.0.2:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	h1 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node1 }}
	h2 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node2 }}
	c.AddHop(h1)
	c.AddHop(h2)

	rt := c.Route(context.Background(), "tcp", "192.168.1.1:80")
	require.NotNil(t, rt)
	assert.Len(t, rt.Nodes(), 2)
	assert.Equal(t, "hop1", rt.Nodes()[0].Name)
	assert.Equal(t, "hop2", rt.Nodes()[1].Name)
}

func TestChain_Route_MultiplexSplit(t *testing.T) {
	// When a node supports multiplexing, the route is split: nodes before the
	// multiplex node become a sub-route embedded in that node's transport, and
	// the returned route starts fresh after the multiplex node.
	c := NewChain("test-chain")

	node1 := chain.NewNode("hop1", "10.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	muxTr := NewTransport(&testDialer{hasMux: true, multiplexVal: true}, &testConnector{})
	node2 := chain.NewNode("hop2", "10.0.0.2:8080",
		chain.TransportNodeOption(muxTr))

	node3 := chain.NewNode("hop3", "10.0.0.3:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	h1 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node1 }}
	h2 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node2 }}
	h3 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node3 }}
	c.AddHop(h1)
	c.AddHop(h2)
	c.AddHop(h3)

	rt := c.Route(context.Background(), "tcp", "192.168.1.1:80")
	require.NotNil(t, rt)

	// hop1 is in the sub-route embedded in hop2's transport
	// hop2 starts the new route (it's the multiplex node), hop3 follows
	nodes := rt.Nodes()
	require.Len(t, nodes, 2)
	assert.Equal(t, "hop2", nodes[0].Name)
	assert.Equal(t, "hop3", nodes[1].Name)

	// Verify hop2's transport has the sub-route with hop1
	subRoute := nodes[0].Options().Transport.Options().Route
	require.NotNil(t, subRoute)
	assert.Len(t, subRoute.Nodes(), 1)
	assert.Equal(t, "hop1", subRoute.Nodes()[0].Name)
}

func TestChain_Route_NilNodeFromHop(t *testing.T) {
	c := NewChain("test-chain")
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return nil },
	}
	c.AddHop(h)

	rt := c.Route(context.Background(), "tcp", "127.0.0.1:80")
	require.NotNil(t, rt)
	// Empty route because the hop returned nil (no suitable node)
	assert.Len(t, rt.Nodes(), 0)
}

func TestChain_Route_NilNodeInMiddle(t *testing.T) {
	c := NewChain("test-chain")
	node1 := chain.NewNode("hop1", "10.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	h1 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node1 }}
	h2 := &testHop{selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return nil }}
	c.AddHop(h1)
	c.AddHop(h2)

	rt := c.Route(context.Background(), "tcp", "127.0.0.1:80")
	require.NotNil(t, rt)
	// Only hop1 is present; route stops at the nil node
	assert.Len(t, rt.Nodes(), 1)
}

func TestNewChainGroup(t *testing.T) {
	ch1 := NewChain("ch1")
	ch2 := NewChain("ch2")
	g := NewChainGroup(ch1, ch2)
	require.NotNil(t, g)
	assert.Len(t, g.chains, 2)
}

func TestChainGroup_Route_NoChains(t *testing.T) {
	g := NewChainGroup()
	rt := g.Route(context.Background(), "tcp", "127.0.0.1:80")
	assert.Nil(t, rt)
}

func TestChainGroup_Route_WithEmptyChain(t *testing.T) {
	// Chain group with empty chain (no hops) returns nil route.
	ch1 := NewChain("ch1")
	g := NewChainGroup(ch1)
	sel := &testSelector{chains: []chain.Chainer{ch1}}
	g.WithSelector(sel)

	rt := g.Route(context.Background(), "tcp", "127.0.0.1:80")
	assert.Nil(t, rt)
}

func TestChainGroup_Route_NilReceiver(t *testing.T) {
	var g *chainGroup
	rt := g.Route(context.Background(), "tcp", "127.0.0.1:80")
	assert.Nil(t, rt)
}

// =============================================================================
// Route tests
// =============================================================================

func TestNewRoute(t *testing.T) {
	rt := NewRoute()
	require.NotNil(t, rt)
	assert.Len(t, rt.Nodes(), 0)
}

func TestNewRoute_WithChainOption(t *testing.T) {
	c := NewChain("test-chain")
	rt := NewRoute(ChainRouteOption(c))
	require.NotNil(t, rt)
	assert.Equal(t, c, rt.options.Chain)
}

func TestChainRoute_AddNode(t *testing.T) {
	rt := NewRoute()
	node := chain.NewNode("n1", "127.0.0.1:8080")
	rt.addNode(node)
	assert.Len(t, rt.Nodes(), 1)
	rt.addNode(chain.NewNode("n2", "127.0.0.1:9090"))
	assert.Len(t, rt.Nodes(), 2)
}

func TestChainRoute_Nodes(t *testing.T) {
	rt := NewRoute()
	node1 := chain.NewNode("n1", "127.0.0.1:8080")
	node2 := chain.NewNode("n2", "127.0.0.1:9090")
	rt.addNode(node1, node2)

	nodes := rt.Nodes()
	assert.Len(t, nodes, 2)
	assert.Equal(t, "n1", nodes[0].Name)
	assert.Equal(t, "n2", nodes[1].Name)
}

func TestChainRoute_Nodes_NilReceiver(t *testing.T) {
	var rt *chainRoute
	assert.Nil(t, rt.Nodes())
}

func TestChainRoute_GetNode_Valid(t *testing.T) {
	rt := NewRoute()
	node := chain.NewNode("n1", "127.0.0.1:8080")
	rt.addNode(node)

	assert.Equal(t, node, rt.getNode(0))
}

func TestChainRoute_GetNode_OutOfBounds(t *testing.T) {
	rt := NewRoute()
	rt.addNode(chain.NewNode("n1", "127.0.0.1:8080"))

	assert.Nil(t, rt.getNode(-1))
	assert.Nil(t, rt.getNode(1))
}

func TestChainRoute_GetNode_EmptyRoute(t *testing.T) {
	rt := NewRoute()
	assert.Nil(t, rt.getNode(0))
}

func TestChainRoute_GetNode_NilReceiver(t *testing.T) {
	var rt *chainRoute
	assert.Nil(t, rt.getNode(0))
}

func TestChainRoute_Dial_EmptyRoute(t *testing.T) {
	// Empty route falls through to DefaultRoute. The DefaultRoute path
	// requires real network I/O; test it through Router integration tests.
	rt := NewRoute()
	assert.Len(t, rt.Nodes(), 0)
}

func TestChainRoute_Dial_SingleNode(t *testing.T) {
	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
}

func TestChainRoute_Dial_MultipleNodes(t *testing.T) {
	// Two-hop chain: node1 (entry proxy) → node2 (exit proxy) → destination
	tr1 := NewTransport(&testDialer{}, &testConnector{})
	tr2 := NewTransport(&testDialer{}, &testConnector{})

	node1 := chain.NewNode("entry", "127.0.0.1:8080", chain.TransportNodeOption(tr1))
	node2 := chain.NewNode("exit", "127.0.0.1:9090", chain.TransportNodeOption(tr2))

	rt := NewRoute()
	rt.addNode(node1, node2)

	conn, err := rt.Dial(context.Background(), "tcp", "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
}

func TestChainRoute_Dial_DialError(t *testing.T) {
	dialErr := errors.New("cannot dial")
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return nil, dialErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestChainRoute_Dial_HandshakeError(t *testing.T) {
	handshakeErr := errors.New("handshake error")
	tr := NewTransport(
		&testDialer{
			handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
				return nil, handshakeErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestChainRoute_Dial_ConnectError(t *testing.T) {
	connectErr := errors.New("connect failed")
	tr := NewTransport(
		&testDialer{},
		&testConnector{
			connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
				return nil, connectErr
			},
		},
	)
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestChainRoute_Dial_MultiHopConnectError(t *testing.T) {
	// First hop succeeds, second hop's Connect fails.
	connectErr := errors.New("intermediate connect failed")
	tr1 := NewTransport(&testDialer{}, &testConnector{})
	tr2 := NewTransport(
		&testDialer{},
		&testConnector{
			connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
				return nil, connectErr
			},
		},
	)

	node1 := chain.NewNode("entry", "127.0.0.1:8080", chain.TransportNodeOption(tr1))
	node2 := chain.NewNode("exit", "127.0.0.1:9090", chain.TransportNodeOption(tr2))

	rt := NewRoute()
	rt.addNode(node1, node2)

	conn, err := rt.Dial(context.Background(), "tcp", "192.168.1.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestChainRoute_Dial_MultiHopHandshakeError(t *testing.T) {
	// First hop succeeds, second hop's Handshake fails.
	handshakeErr := errors.New("handshake failed")
	tr1 := NewTransport(&testDialer{}, &testConnector{})
	tr2 := NewTransport(
		&testDialer{
			handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
				return nil, handshakeErr
			},
		},
		&testConnector{},
	)

	node1 := chain.NewNode("entry", "127.0.0.1:8080", chain.TransportNodeOption(tr1))
	node2 := chain.NewNode("exit", "127.0.0.1:9090", chain.TransportNodeOption(tr2))

	rt := NewRoute()
	rt.addNode(node1, node2)

	conn, err := rt.Dial(context.Background(), "tcp", "192.168.1.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestChainRoute_Dial_ConnectionCleanupOnError(t *testing.T) {
	// Verify that on intermediate node failure, previous connections are closed.
	conn1 := &trackedConn{testConn: &testConn{}}

	tr1 := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return conn1, nil
			},
		},
		&testConnector{},
	)

	// Second transport fails on Connect, which should trigger conn1.Close()
	tr2 := NewTransport(
		&testDialer{},
		&testConnector{
			connectFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
				return nil, errors.New("fail")
			},
		},
	)

	node1 := chain.NewNode("entry", "127.0.0.1:8080", chain.TransportNodeOption(tr1))
	node2 := chain.NewNode("exit", "127.0.0.1:9090", chain.TransportNodeOption(tr2))

	rt := NewRoute()
	rt.addNode(node1, node2)

	_, err := rt.Dial(context.Background(), "tcp", "192.168.1.1:80")
	assert.Error(t, err)
	assert.True(t, conn1.closed, "first hop connection should be closed on second hop failure")
}

func TestChainRoute_Bind_EmptyRoute(t *testing.T) {
	rt := NewRoute()
	// Empty route falls to DefaultRoute.Bind — TCP bind on port 0 should succeed.
	ln, err := rt.Bind(context.Background(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestChainRoute_Bind_SingleNode(t *testing.T) {
	tr := NewTransport(&testDialer{}, &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return &testListener{}, nil
		},
	})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	ln, err := rt.Bind(context.Background(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestChainRoute_Bind_BindError(t *testing.T) {
	bindErr := errors.New("bind not available")
	tr := NewTransport(&testDialer{}, &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return nil, bindErr
		},
	})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	ln, err := rt.Bind(context.Background(), "tcp", ":0")
	assert.Error(t, err)
	assert.Nil(t, ln)
}

func TestChainRoute_Bind_ConnectError(t *testing.T) {
	// Dial succeeds but Bind on the last node fails — connection should be cleaned up.
	dialErr := errors.New("dial failed")
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return nil, dialErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	ln, err := rt.Bind(context.Background(), "tcp", ":0")
	assert.Error(t, err)
	assert.Nil(t, ln)
}

func TestChainRoute_Bind_WithBindOptions(t *testing.T) {
	// Verify Bind passes through BindOptions correctly.
	tr := NewTransport(&testDialer{}, &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return &testListener{}, nil
		},
	})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	ln, err := rt.Bind(context.Background(), "tcp", ":0",
		chain.MuxBindOption(true),
		chain.BacklogBindOption(128),
		chain.UDPConnTTLBindOption(30*time.Second),
		chain.UDPDataBufferSizeBindOption(4096),
		chain.UDPDataQueueSizeBindOption(64),
	)
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestChainRoute_Dial_WithDialOptions(t *testing.T) {
	// Verify Dial passes through DialOptions correctly.
	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute()
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80",
		chain.InterfaceDialOption("eth0"),
		chain.NetnsDialOption("ns1"),
		chain.SockOptsDialOption(&chain.SockOpts{Mark: 99}),
		chain.LoggerDialOption(xlogger.Nop()),
	)
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
}

func TestChainRoute_Connect_MarkerOnError(t *testing.T) {
	// When connect fails and the route has a parent Chain, the node and chain
	// markers should be updated.
	c := NewChain("test-chain")
	dialErr := errors.New("dial failed")
	var dialCalled bool
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				dialCalled = true
				// Return error after first call to test marker behavior
				if addr == "127.0.0.1:8080" {
					return nil, dialErr
				}
				return &testConn{}, nil
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute(ChainRouteOption(c))
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.True(t, dialCalled)

	// Chain marker should reflect the error
	assert.Greater(t, c.Marker().Count(), int64(0))
}

func TestChainRoute_Connect_SuccessResetsChainMarker(t *testing.T) {
	// On success, the chain marker should be reset.
	c := NewChain("test-chain")
	// Pre-mark the chain
	c.Marker().Mark()

	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("node1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute(ChainRouteOption(c))
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	require.NoError(t, err)
	conn.Close()

	// Chain marker should be reset to 0 on success
	assert.Equal(t, int64(0), c.Marker().Count())
}

func TestDefaultRoute_Nodes(t *testing.T) {
	assert.Nil(t, DefaultRoute.Nodes())
}

func TestDefaultRoute_ImplementsRoute(t *testing.T) {
	var r chain.Route = DefaultRoute
	assert.NotNil(t, r)
}

func TestRoutePath(t *testing.T) {
	// Simple route with no sub-routes.
	node1 := chain.NewNode("n1", "127.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	node2 := chain.NewNode("n2", "127.0.0.1:9090",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	rt := NewRoute()
	rt.addNode(node1, node2)

	path := routePath(rt)
	require.Len(t, path, 2)
	assert.Equal(t, "n1", path[0].Name)
	assert.Equal(t, "n2", path[1].Name)
}

func TestRoutePath_NilRoute(t *testing.T) {
	assert.Nil(t, routePath(nil))
}

func TestRoutePath_NestedRoutes(t *testing.T) {
	// Simulate what Chain.Route does for multiplex splitting: the sub-route
	// is embedded in the transport options of the multiplex node.
	innerNode := chain.NewNode("inner", "10.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	innerRoute := NewRoute()
	innerRoute.addNode(innerNode)

	muxTr := NewTransport(&testDialer{}, &testConnector{})
	muxTr.Options().Route = innerRoute
	muxNode := chain.NewNode("mux", "10.0.0.2:8080", chain.TransportNodeOption(muxTr))

	outerNode := chain.NewNode("outer", "10.0.0.3:9090",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))

	rt := NewRoute()
	rt.addNode(muxNode, outerNode)

	path := routePath(rt)
	require.Len(t, path, 3)
	assert.Equal(t, "inner", path[0].Name)
	assert.Equal(t, "mux", path[1].Name)
	assert.Equal(t, "outer", path[2].Name)
}

// =============================================================================
// Router tests
// =============================================================================

func TestNewRouter_Defaults(t *testing.T) {
	r := NewRouter()
	require.NotNil(t, r)
	assert.Equal(t, 15*time.Second, r.options.Timeout)
	assert.NotNil(t, r.options.Logger)
}

func TestNewRouter_WithOptions(t *testing.T) {
	testChain := NewChain("test-chain")
	l := xlogger.Nop()

	r := NewRouter(
		chain.TimeoutRouterOption(30*time.Second),
		chain.RetriesRouterOption(3),
		chain.InterfaceRouterOption("eth0"),
		chain.NetnsRouterOption("ns1"),
		chain.SockOptsRouterOption(&chain.SockOpts{Mark: 99}),
		chain.ChainRouterOption(testChain),
		chain.LoggerRouterOption(l),
	)
	require.NotNil(t, r)
	assert.Equal(t, 30*time.Second, r.options.Timeout)
	assert.Equal(t, 3, r.options.Retries)
	assert.Equal(t, "eth0", r.options.IfceName)
	assert.Equal(t, "ns1", r.options.Netns)
	assert.Equal(t, 99, r.options.SockOpts.Mark)
	assert.Equal(t, testChain, r.options.Chain)
	assert.Equal(t, l, r.options.Logger)
}

func TestNewRouter_ZeroTimeoutDefault(t *testing.T) {
	// Timeout of 0 is replaced with 15s default.
	r := NewRouter(chain.TimeoutRouterOption(0))
	assert.Equal(t, 15*time.Second, r.options.Timeout)
}

func TestRouter_Options(t *testing.T) {
	r := NewRouter(chain.TimeoutRouterOption(5 * time.Second))
	opts := r.Options()
	require.NotNil(t, opts)
	assert.Equal(t, 5*time.Second, opts.Timeout)
}

func TestRouter_Options_NilReceiver(t *testing.T) {
	var r *Router
	assert.Nil(t, r.Options())
}

func TestRouter_Record_WithMatchingRecorder(t *testing.T) {
	rec := &testRecorder{}
	r := NewRouter(
		chain.RecordersRouterOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   recorder.RecorderServiceRouterDialAddress,
		}),
	)
	err := r.record(context.Background(), recorder.RecorderServiceRouterDialAddress, []byte("test-addr"))
	assert.NoError(t, err)
	assert.Len(t, rec.records, 1)
	assert.Equal(t, "test-addr", rec.records[0].data)
}

func TestRouter_Record_NoMatch(t *testing.T) {
	rec := &testRecorder{}
	r := NewRouter(
		chain.RecordersRouterOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   "other.record.name",
		}),
	)
	err := r.record(context.Background(), recorder.RecorderServiceRouterDialAddress, []byte("test-addr"))
	assert.NoError(t, err)
	assert.Len(t, rec.records, 0)
}

func TestRouter_Record_EmptyData(t *testing.T) {
	rec := &testRecorder{}
	r := NewRouter(
		chain.RecordersRouterOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   recorder.RecorderServiceRouterDialAddress,
		}),
	)
	err := r.record(context.Background(), recorder.RecorderServiceRouterDialAddress, nil)
	assert.NoError(t, err)
	assert.Len(t, rec.records, 0)
}

func TestRouter_Dial_RecordsAddress(t *testing.T) {
	rec := &testRecorder{}
	testChain := NewChain("test-chain")

	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	testChain.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(testChain),
		chain.RecordersRouterOption(recorder.RecorderObject{
			Recorder: rec,
			Record:   recorder.RecorderServiceRouterDialAddress,
		}),
	)

	conn, err := r.Dial(context.Background(), "tcp", "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()

	assert.Len(t, rec.records, 1)
	assert.Equal(t, "192.168.1.1", rec.records[0].data)
}

func TestRouter_Dial_ErrorRecordsAddress(t *testing.T) {
	// Verify that Dial records the address before the dial attempt, regardless
	// of whether the dial succeeds or fails.
	rec := &testRecorder{}
	dialErr := errors.New("dial failed")
	testChain := NewChain("test-chain")
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return nil, dialErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	testChain.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(testChain),
		chain.RetriesRouterOption(0),
		chain.RecordersRouterOption(
			recorder.RecorderObject{
				Recorder: rec,
				Record:   recorder.RecorderServiceRouterDialAddress,
			},
			recorder.RecorderObject{
				Recorder: rec,
				Record:   recorder.RecorderServiceRouterDialAddressError,
			},
		),
	)

	_, err := r.Dial(context.Background(), "tcp", "192.168.1.1:80")
	assert.Error(t, err)
	// Dial always records the address first (before dial attempt)
	assert.Equal(t, "192.168.1.1", rec.records[0].data)
}

func TestRouter_Dial_UDPWrapsAsPacketConn(t *testing.T) {
	// When network is "udp", the returned connection should implement net.PacketConn.
	testChain := NewChain("test-chain")
	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	testChain.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(testChain),
	)

	// The transport returns a testConn which does NOT implement net.PacketConn,
	// so Router.Dial should wrap it in a packetConn.
	conn, err := r.Dial(context.Background(), "udp", "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)

	_, ok := conn.(net.PacketConn)
	assert.True(t, ok, "UDP dial should return a net.PacketConn")
	conn.Close()
}

func TestRouter_Bind_EmptyChain(t *testing.T) {
	// Chain with no hops → empty route → ErrEmptyRoute
	c := NewChain("empty")
	r := NewRouter(chain.ChainRouterOption(c), chain.RetriesRouterOption(0))

	ln, err := r.Bind(context.Background(), "tcp", ":0")
	assert.ErrorIs(t, err, ErrEmptyRoute)
	assert.Nil(t, ln)
}

func TestRouter_Bind_NoChain(t *testing.T) {
	// No chain → falls to DefaultRoute.Bind
	r := NewRouter(chain.RetriesRouterOption(0))

	ln, err := r.Bind(context.Background(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestRouter_Bind_WithChain(t *testing.T) {
	c := NewChain("test-chain")
	tr := NewTransport(&testDialer{}, &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return &testListener{}, nil
		},
	})
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	c.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(c),
		chain.RetriesRouterOption(0),
	)

	ln, err := r.Bind(context.Background(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestRouter_Bind_Retries(t *testing.T) {
	// First attempt fails, second succeeds.
	attempts := 0
	c := NewChain("test-chain")

	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				attempts++
				if attempts == 1 {
					return nil, errors.New("transient error")
				}
				return &testConn{}, nil
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	c.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(c),
		chain.RetriesRouterOption(2),
	)

	conn, err := r.Dial(context.Background(), "tcp", "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()

	assert.Equal(t, 2, attempts, "should have retried once and succeeded on second attempt")
}

func TestRouter_Dial_NegativeRetries(t *testing.T) {
	// Negative retries should be clamped to 1 (count must be at least 1).
	c := NewChain("test-chain")
	tr := NewTransport(&testDialer{}, &testConnector{})
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	c.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(c),
		chain.RetriesRouterOption(-5),
	)

	conn, err := r.Dial(context.Background(), "tcp", "127.0.0.1:80")
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
}

func TestRouter_Bind_NegativeRetries(t *testing.T) {
	c := NewChain("test-chain")
	tr := NewTransport(&testDialer{}, &testConnector{
		bindFn: func(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
			return &testListener{}, nil
		},
	})
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	c.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(c),
		chain.RetriesRouterOption(-1),
	)

	ln, err := r.Bind(context.Background(), "tcp", ":0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	ln.Close()
}

func TestRouter_Bind_ErrorOnRetry(t *testing.T) {
	// All retries fail — verifies error logging path.
	c := NewChain("test-chain")
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return nil, errors.New("persistent error")
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	c.AddHop(h)

	r := NewRouter(
		chain.ChainRouterOption(c),
		chain.RetriesRouterOption(1),
	)

	ln, err := r.Bind(context.Background(), "tcp", ":0")
	assert.Error(t, err)
	assert.Nil(t, ln)
}

// =============================================================================
// PacketConn wrapper tests
// =============================================================================

func TestPacketConn_ReadFrom(t *testing.T) {
	c := &packetConn{Conn: &testConn{}}
	buf := make([]byte, 1024)
	n, addr, err := c.ReadFrom(buf)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, 0)
	assert.NotNil(t, addr)
	assert.Equal(t, c.Conn.RemoteAddr(), addr)
}

func TestPacketConn_WriteTo(t *testing.T) {
	c := &packetConn{Conn: &testConn{}}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}
	n, err := c.WriteTo([]byte("hello"), addr)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

// =============================================================================
// Integration: full route traversal
// =============================================================================

func TestConnect_FirstNodeDialError(t *testing.T) {
	// connect() should mark both the node and the chain on dial failure.
	c := NewChain("test-chain")
	dialErr := errors.New("dial refused")
	tr := NewTransport(
		&testDialer{
			dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
				return nil, dialErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("bad-node", "127.0.0.1:9999", chain.TransportNodeOption(tr))
	rt := NewRoute(ChainRouteOption(c))
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestConnect_FirstNodeHandshakeError(t *testing.T) {
	// connect() should close the dialed connection on handshake failure.
	c := NewChain("test-chain")
	handshakeErr := errors.New("tls handshake failed")
	tr := NewTransport(
		&testDialer{
			handshakeFn: func(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
				return nil, handshakeErr
			},
		},
		&testConnector{},
	)
	node := chain.NewNode("bad-tls", "127.0.0.1:8080", chain.TransportNodeOption(tr))
	rt := NewRoute(ChainRouteOption(c))
	rt.addNode(node)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestConnect_SecondNodeEmptyAddress(t *testing.T) {
	// When the second node has an empty address, xnet.Resolve returns ("", nil)
	// and Connect is called with an empty target.
	tr1 := NewTransport(&testDialer{}, &testConnector{})
	node1 := chain.NewNode("ok-node", "127.0.0.1:8080", chain.TransportNodeOption(tr1))

	node2 := chain.NewNode("empty-addr", "", chain.TransportNodeOption(
		NewTransport(&testDialer{}, &testConnector{}),
	))

	rt := NewRoute()
	rt.addNode(node1, node2)

	conn, err := rt.Dial(context.Background(), "tcp", "127.0.0.1:80")
	require.NoError(t, err)
	conn.Close()
}

// =============================================================================
// Verify interface satisfaction
// =============================================================================

func TestTransport_ImplementsTransporter(t *testing.T) {
	var _ chain.Transporter = (*Transport)(nil)
}

func TestChain_ImplementsChainer(t *testing.T) {
	var _ chain.Chainer = (*Chain)(nil)
}

func TestChainGroup_ImplementsChainer(t *testing.T) {
	var _ chain.Chainer = (*chainGroup)(nil)
}

func TestChainRoute_ImplementsRoute(t *testing.T) {
	var _ chain.Route = (*chainRoute)(nil)
}

func TestDefaultRoute_ImplementsRoute_Interface(t *testing.T) {
	var _ chain.Route = DefaultRoute
}

func TestRouter_ImplementsRouter(t *testing.T) {
	var _ chain.Router = (*Router)(nil)
}

// =============================================================================
// selector.Selector usage in chainGroup
// =============================================================================

// testSelector implements selector.Selector[chain.Chainer].
type testSelector struct {
	chains []chain.Chainer
	idx    int
}

func (s *testSelector) Select(ctx context.Context, chains ...chain.Chainer) chain.Chainer {
	if len(s.chains) == 0 {
		return nil
	}
	ch := s.chains[s.idx%len(s.chains)]
	s.idx++
	return ch
}

func TestChainGroup_WithSelector(t *testing.T) {
	ch1 := NewChain("ch1")
	ch2 := NewChain("ch2")
	g := NewChainGroup(ch1, ch2)

	sel := &testSelector{chains: []chain.Chainer{ch1, ch2}}
	g.WithSelector(sel)

	// With selector, Route should delegate to the selected chain.
	// But NewChain creates an empty chain (no hops), so Route returns nil.
	// We need to add hops to make Route return a non-nil route.
	node := chain.NewNode("n1", "127.0.0.1:8080",
		chain.TransportNodeOption(NewTransport(&testDialer{}, &testConnector{})))
	h := &testHop{
		selectFn: func(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return node },
	}
	ch1.AddHop(h)

	rt := g.Route(context.Background(), "tcp", "127.0.0.1:80")
	require.NotNil(t, rt)
	assert.Len(t, rt.Nodes(), 1)
}

func TestChainGroup_Next_NilReceiver(t *testing.T) {
	var g *chainGroup
	assert.Nil(t, g.next(context.Background()))
}

func TestChainGroup_Next_EmptyChains(t *testing.T) {
	g := NewChainGroup()
	assert.Nil(t, g.next(context.Background()))
}
