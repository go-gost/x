package tun

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	tun_util "github.com/go-gost/x/internal/util/tun"
	xlogger "github.com/go-gost/x/logger"
)

// p2pHandler is the tun hub's p2p door: one p2pHub for the life of the handler,
// and one read loop per accepted peer stream feeding it.
//
// It exists because a p2p hub has no socket to loop on. server.go's transportServer
// reads the device in one goroutine and the peers in another, all inside a single
// Handle over a UDP conn; here the peers arrive one at a time as streams from the
// p2p endpoint, so the hub has to outlive them. Everything below that — the
// table, the router, the hub — is the same code the socket path and p2p_test.go
// already share; what is new is only who owns the device reader and who feeds a
// stream to it.
//
// Unlike tunHandler, this one is not built from metadata: the device and its own
// addresses are all fixed before the p2p endpoint can accept a single stream, so
// Init has nothing left to parse.
type p2pHandler struct {
	device net.Conn
	hub    *p2pHub
	router *peerRouter
	log    logger.Logger

	closeOnce sync.Once
}

// NewP2PHandler builds a hub over device — the tun conn the listener produced —
// for the peers that reach it over p2p. authorizer decides which addresses a
// peer's registration may claim, and may be nil when a peer is to be able to
// claim whatever it asks for.
//
// There is no auther here, because a p2p peer has nothing to authenticate: the
// allowlist that routed its stream here already said who it is, and onKeepalive
// consults an auther with the *claimed address* as the user name — so a
// credential check could only ever ask "is this peer allowed the address it just
// claimed", which is the question authorizer answers, and which an operator could
// otherwise satisfy only by typing each spoke's own IP into the tunnel's username
// field.
//
// The hub's device reader starts here and runs until Close, so a packet off the
// device is being routed before the first stream arrives.
func NewP2PHandler(device net.Conn, authorizer PeerAuthorizer, opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	log := options.Logger
	if log == nil {
		log = xlogger.Nop()
	}

	// A p2p hub has no TTL: a peer announces its departure by closing its
	// stream, and peerGone reclaims exactly that peer's routes on the way out.
	// A timer here would only guess at what the close says outright.
	//
	// A nil authorizer means "register whatever a peer claims", which is also
	// what the socket hub's table means by having none. On the table itself the
	// authorizer is a variadic option rather than a parameter because every
	// existing caller means "no address authorization"; here it arrives as an
	// argument so a hub's owner has one place to pass it. The auther stays nil
	// throughout: this path has no credential to check, because the p2p peer
	// allowlist already decided which peers may connect at all.
	table := newPeerTable(nil, 0, options.Service, log, withAuthorizer(authorizer))
	router := newPeerRouter(table)

	h := &p2pHandler{
		device: device,
		router: router,
		log:    log,
		hub:    newP2PHub(device, router, deviceNets(device, log), func(msg string) { log.Warn(msg) }),
	}

	go func() {
		// The device closing under its reader is how this hub stops, so run
		// reports it wrapped as ErrTun and it is logged at debug rather than as
		// the failure it would otherwise read as. There is no caller to return
		// it to: the handler is closed by its service, not by its device.
		if err := h.hub.run(); err != nil && !errors.Is(err, ErrTun) {
			log.Errorf("tun device: %v", err)
		} else {
			log.Debug("tun device closed")
		}
	}()

	return h
}

// Init is a no-op. The device and its own addresses are all fixed at
// construction — the config that describes them lives on the device conn's
// context, which exists before any metadata does — and the p2p endpoint that
// builds this handler is what turns config into them.
func (h *p2pHandler) Init(md md.Metadata) error { return nil }

// Handle runs one accepted peer stream for as long as it lives.
//
// The stream is keyed by its remote address, which is the peer key the p2p host
// stamped on the conn — not an address, and never parsed as one. Installing it
// replaces whatever held that key, so a peer that reconnected is immediately the
// one packets are written to and the old stream, which is on its way out, is not.
//
// Teardown goes through peerGone and nothing else: it reclaims the peer's routes
// only while this stream still holds its key, so a stale stream ending cannot
// cut off the live connection its peer already replaced it with. It also closes
// the conn, which is what satisfies the Handler contract that the connection is
// closed when Handle returns.
func (h *p2pHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	s := newPeerStream(ctx, conn.RemoteAddr().String(), conn)
	h.router.install(s)
	h.log.Debugf("peer %s connected", s.key)

	defer h.hub.peerGone(s)

	var b [MaxMessageSize]byte
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := conn.Read(b[:])
		if err != nil {
			// Returned as-is, and that is the whole convention: a stream that ends
			// is io.EOF, a closed conn is net.ErrClosed, and a torn-down context is
			// context.Canceled — service.Serve reads each of those as an ordinary
			// end and logs it at debug, while anything else is a failure. Wrapping
			// them here would put a normal reconnect in someone's error log.
			return err
		}
		if n == 0 {
			continue
		}
		// fromSpoke answers a keepalive on the stream it arrived on and hands
		// anything else to the device under the hub's write lock; the hub logs
		// its own routing warnings, so a failure here is the write itself.
		if err := h.hub.fromSpoke(s, b[:n]); err != nil {
			h.log.Warnf("peer %s: %v", s.key, err)
			return err
		}
	}
}

// Close stops the device reader. The device is what the reader is blocked in, so
// closing it is the stop; the loop's own error is logged where it ends rather
// than returned, since a handler is closed by its service, not by its peer.
func (h *p2pHandler) Close() error {
	h.closeOnce.Do(func() { h.device.Close() })
	return nil
}

// deviceNets reads the hub's own networks off the device conn's context — the
// same place, and the same two steps, as server.go's Handle reads the device's
// config. It is a separate function only because it is wanted at construction,
// before there is a Handle to read it in.
//
// It is not optional plumbing: with a nil answer peerTable's self-loop guard has
// nothing to compare against and silently stops refusing, and a peer that
// registered the hub's own address would then have the hub's own packets routed
// back into it. So a device that carries no config is logged rather than passed
// over.
func deviceNets(device net.Conn, log logger.Logger) []net.IPNet {
	var config *tun_util.Config
	if c, ok := device.(xctx.Context); ok && c.Context() != nil {
		if m := ictx.MetadataFromContext(c.Context()); m != nil {
			config, _ = m.Get("config").(*tun_util.Config)
		}
	}
	if config == nil {
		log.Warn("tun device: no config on the device conn, the self-route guard is disabled")
		return nil
	}
	return config.Net
}

var _ handler.Handler = (*p2pHandler)(nil)
