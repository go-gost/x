package mux

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	xctx "github.com/go-gost/x/ctx"
	"github.com/hashicorp/yamux"
	smux "github.com/xtaci/smux"
)

const (
	defaultVersion = 1

	// defaultOpenTimeout bounds a stream open whose caller cannot say how long
	// it may take.
	defaultOpenTimeout = 15 * time.Second
)

// ErrOpenTimeout reports that a stream open exceeded its bound. The session is
// left open: closing it is the caller's decision.
var ErrOpenTimeout = errors.New("mux: open stream timeout")

type Config struct {
	// Type selects the mux backend: "smux" (default) or "yamux".
	Type string

	// SMUX Protocol version, support 1,2
	Version int

	// Disabled keepalive
	KeepAliveDisabled bool

	// KeepAliveInterval is how often to send a NOP command to the remote
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is how long the session
	// will be closed if no data has arrived
	KeepAliveTimeout time.Duration

	// MaxFrameSize is used to control the maximum
	// frame size to sent to the remote
	MaxFrameSize int

	// MaxReceiveBuffer is used to control the maximum
	// number of data in the buffer pool
	MaxReceiveBuffer int

	// MaxStreamBuffer is used to control the maximum
	// number of data per stream
	MaxStreamBuffer int

	// MaxStreamWindow is the yamux MaxStreamWindowSize in bytes.
	MaxStreamWindow int

	// OpenTimeout bounds a stream open. Zero selects defaultOpenTimeout.
	OpenTimeout time.Duration
}

// Session multiplexes streams over a single underlying connection.
type Session interface {
	// GetConn opens a stream, bounded by defaultOpenTimeout.
	GetConn() (net.Conn, error)
	// GetConnContext opens a stream bounded by ctx as well.
	GetConnContext(ctx context.Context) (net.Conn, error)
	Accept() (net.Conn, error)
	Close() error
	IsClosed() bool
}

// openBound returns how long an open may take, and whether the caller's
// context is the tighter of the two bounds.
func openBound(ctx context.Context, timeout time.Duration) (time.Duration, bool) {
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < timeout {
			return left, true
		}
	}
	return timeout, false
}

// openAwaited runs open aside and waits for it, bounded by ctx and timeout.
// Both backends have their own fixed open timeout (smux 30s, yamux 75s) that
// ignores ctx, hence the race. Whichever bound is tighter decides the error
// that is reported, so a caller's deadline is never disguised as a mux timeout.
func openAwaited(ctx context.Context, timeout time.Duration, open func() (any, error)) (any, error) {
	type result struct {
		v   any
		err error
	}

	ch := make(chan result, 1)
	go func() {
		v, err := open()
		ch <- result{v: v, err: err}
	}()

	bound, ctxBound := openBound(ctx, timeout)
	var expired <-chan time.Time
	if !ctxBound {
		timer := time.NewTimer(bound)
		defer timer.Stop()
		expired = timer.C
	}

	select {
	case r := <-ch:
		return r.v, r.err
	case <-expired:
	case <-ctx.Done():
	}

	// The open may still succeed later; that stream has no owner left.
	go func() {
		if r := <-ch; r.err == nil {
			if c, ok := r.v.(net.Conn); ok && c != nil {
				c.Close()
			}
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrOpenTimeout
}

func muxType(cfg *Config) string {
	if cfg == nil {
		return "smux"
	}
	if cfg.Type == "" {
		return "smux"
	}
	return cfg.Type
}

// ClientSession creates a client-side mux session over conn.
func ClientSession(conn net.Conn, cfg *Config) (Session, error) {
	if muxType(cfg) == "yamux" {
		return newYamuxClientSession(conn, cfg)
	}
	return newSMUXClientSession(conn, cfg)
}

// sessionStall watches a session's send path. A stream write that times out
// means its frame never reached the socket, and nothing else notices: the
// session's keepalive only tracks received frames, so a peer that keeps sending
// while it stops reading leaves the session open forever and every new stream
// stalls on it. Closing the session is the only signal its owner can act on —
// it retires the closed session and dials a new tunnel.
type sessionStall struct {
	suspect atomic.Bool
	close   func() error
}

// observe records the outcome of one stream write. A successful write clears
// the pending strike; two timed-out writes without one in between close the
// session. A yamux connection write timeout is final on its own: yamux blocks
// the following write of that stream indefinitely.
//
// The close runs on its own goroutine: yamux's Close waits for the send loop,
// and the send loop is the goroutine this write path is blocked behind.
func (s *sessionStall) observe(err error) {
	if s == nil {
		return
	}
	if err == nil {
		s.suspect.Store(false)
		return
	}
	if errors.Is(err, yamux.ErrConnectionWriteTimeout) {
		go s.close()
		return
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		return
	}
	if s.suspect.Swap(true) {
		go s.close()
	}
}

// ServerSession creates a server-side mux session over conn.
func ServerSession(conn net.Conn, cfg *Config) (Session, error) {
	if muxType(cfg) == "yamux" {
		return newYamuxServerSession(conn, cfg)
	}
	return newSMUXServerSession(conn, cfg)
}

// --- SMUX backend ---

func convertConfig(cfg *Config) *smux.Config {
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = defaultVersion

	if cfg == nil {
		return smuxCfg
	}

	if cfg.Version > 0 {
		smuxCfg.Version = cfg.Version
	}
	smuxCfg.KeepAliveDisabled = cfg.KeepAliveDisabled
	if cfg.KeepAliveInterval > 0 {
		smuxCfg.KeepAliveInterval = cfg.KeepAliveInterval
	}
	if cfg.KeepAliveTimeout > 0 {
		smuxCfg.KeepAliveTimeout = cfg.KeepAliveTimeout
	}
	if cfg.MaxFrameSize > 0 {
		smuxCfg.MaxFrameSize = cfg.MaxFrameSize
	}
	if cfg.MaxReceiveBuffer > 0 {
		smuxCfg.MaxReceiveBuffer = cfg.MaxReceiveBuffer
	}
	if cfg.MaxStreamBuffer > 0 {
		smuxCfg.MaxStreamBuffer = cfg.MaxStreamBuffer
	}

	return smuxCfg
}

type smuxSession struct {
	conn        net.Conn
	session     *smux.Session
	stall       *sessionStall
	openTimeout time.Duration
}

func newSMUXClientSession(conn net.Conn, cfg *Config) (Session, error) {
	s, err := smux.Client(conn, convertConfig(cfg))
	if err != nil {
		return nil, err
	}
	ss := &smuxSession{
		conn:    conn,
		session: s,
	}
	ss.init(cfg)
	return ss, nil
}

func newSMUXServerSession(conn net.Conn, cfg *Config) (Session, error) {
	s, err := smux.Server(conn, convertConfig(cfg))
	if err != nil {
		return nil, err
	}
	ss := &smuxSession{
		conn:    conn,
		session: s,
	}
	ss.init(cfg)
	return ss, nil
}

func (session *smuxSession) init(cfg *Config) {
	session.stall = &sessionStall{close: session.Close}
	if cfg != nil {
		session.openTimeout = cfg.OpenTimeout
	}
}

func (session *smuxSession) GetConn() (net.Conn, error) {
	return session.GetConnContext(context.Background())
}

func (session *smuxSession) GetConnContext(ctx context.Context) (net.Conn, error) {
	v, err := openAwaited(ctx, session.openTimeout, func() (any, error) {
		return session.session.OpenStream()
	})
	if err != nil {
		return nil, err
	}
	return &streamConn{Conn: session.conn, stream: v.(*smux.Stream), stall: session.stall}, nil
}

func (session *smuxSession) Accept() (net.Conn, error) {
	stream, err := session.session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Conn: session.conn, stream: stream, stall: session.stall}, nil
}

func (session *smuxSession) Close() error {
	if session.session == nil {
		return nil
	}
	return session.session.Close()
}

func (session *smuxSession) IsClosed() bool {
	if session.session == nil {
		return true
	}
	return session.session.IsClosed()
}

type streamConn struct {
	net.Conn
	stream *smux.Stream
	stall  *sessionStall
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	return c.stream.Read(b)
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	n, err = c.stream.Write(b)
	c.stall.observe(err)
	return
}

func (c *streamConn) Close() error {
	return c.stream.Close()
}

// SetReadDeadline sets the deadline on this stream, never on the session conn
// underneath. The embedded net.Conn is shared by every stream, so a deadline
// set there outlives the stream that set it: net/http parks a read with
// SetReadDeadline(time.Unix(1, 0)) to unblock it on teardown and only clears
// it when a read was actually in flight, leaving the shared conn with a
// deadline in 1970 — and the next session Accept fails with an i/o timeout.
func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline on this stream, never on the session conn
// underneath. See SetReadDeadline.
func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// SetDeadline sets both deadlines on this stream, never on the session conn
// underneath. See SetReadDeadline.
func (c *streamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *streamConn) Context() context.Context {
	if sc, ok := c.Conn.(xctx.Context); ok {
		return sc.Context()
	}
	return nil
}

// --- Yamux backend ---

func convertYamuxConfig(cfg *Config) *yamux.Config {
	yamuxCfg := yamux.DefaultConfig()

	if cfg == nil {
		return yamuxCfg
	}

	if cfg.KeepAliveInterval > 0 {
		yamuxCfg.KeepAliveInterval = cfg.KeepAliveInterval
	}
	if cfg.KeepAliveDisabled {
		yamuxCfg.EnableKeepAlive = false
	}
	if cfg.MaxStreamWindow > 0 {
		yamuxCfg.MaxStreamWindowSize = uint32(cfg.MaxStreamWindow)
	}

	return yamuxCfg
}

type yamuxSession struct {
	conn        net.Conn
	session     *yamux.Session
	stall       *sessionStall
	openTimeout time.Duration
}

func newYamuxClientSession(conn net.Conn, cfg *Config) (Session, error) {
	s, err := yamux.Client(conn, convertYamuxConfig(cfg))
	if err != nil {
		return nil, err
	}
	ys := &yamuxSession{
		conn:    conn,
		session: s,
	}
	ys.init(cfg)
	return ys, nil
}

func newYamuxServerSession(conn net.Conn, cfg *Config) (Session, error) {
	s, err := yamux.Server(conn, convertYamuxConfig(cfg))
	if err != nil {
		return nil, err
	}
	ys := &yamuxSession{
		conn:    conn,
		session: s,
	}
	ys.init(cfg)
	return ys, nil
}

func (session *yamuxSession) init(cfg *Config) {
	session.stall = &sessionStall{close: session.Close}
	if cfg != nil {
		session.openTimeout = cfg.OpenTimeout
	}
}

func (session *yamuxSession) GetConn() (net.Conn, error) {
	return session.GetConnContext(context.Background())
}

func (session *yamuxSession) GetConnContext(ctx context.Context) (net.Conn, error) {
	v, err := openAwaited(ctx, session.openTimeout, func() (any, error) {
		return session.session.Open()
	})
	if err != nil {
		return nil, err
	}
	return &yamuxStreamConn{Conn: session.conn, stream: v.(net.Conn), stall: session.stall}, nil
}

func (session *yamuxSession) Accept() (net.Conn, error) {
	stream, err := session.session.Accept()
	if err != nil {
		return nil, err
	}
	return &yamuxStreamConn{Conn: session.conn, stream: stream, stall: session.stall}, nil
}

func (session *yamuxSession) Close() error {
	if session.session == nil {
		return nil
	}
	return session.session.Close()
}

func (session *yamuxSession) IsClosed() bool {
	if session.session == nil {
		return true
	}
	return session.session.IsClosed()
}

type yamuxStreamConn struct {
	net.Conn
	stream net.Conn
	stall  *sessionStall
}

func (c *yamuxStreamConn) Read(b []byte) (n int, err error) {
	return c.stream.Read(b)
}

func (c *yamuxStreamConn) Write(b []byte) (n int, err error) {
	n, err = c.stream.Write(b)
	c.stall.observe(err)
	return
}

func (c *yamuxStreamConn) Close() error {
	return c.stream.Close()
}

// SetReadDeadline sets the deadline on this stream, never on the session conn
// underneath. See streamConn.SetReadDeadline for why a leaked deadline here
// breaks every other stream on the session.
func (c *yamuxStreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline on this stream, never on the session conn
// underneath. See streamConn.SetReadDeadline.
func (c *yamuxStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// SetDeadline sets both deadlines on this stream, never on the session conn
// underneath. See streamConn.SetReadDeadline.
func (c *yamuxStreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *yamuxStreamConn) Context() context.Context {
	if sc, ok := c.Conn.(xctx.Context); ok {
		return sc.Context()
	}
	return nil
}
