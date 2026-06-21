package quic

import (
	"context"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	icmp_pkg "github.com/go-gost/x/internal/util/icmp"
	"github.com/go-gost/x/registry"
	"github.com/quic-go/quic-go"
)

func init() {
	registry.DialerRegistry().Register("icmp", NewDialer)
	registry.DialerRegistry().Register("icmp6", NewDialer6)
}

type icmpDialer struct {
	ip6          bool
	sessions     map[string]*quicSession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &icmpDialer{
		sessions: make(map[string]*quicSession),
		logger:   options.Logger,
		options:  options,
	}
}

func NewDialer6(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &icmpDialer{
		ip6:      true,
		sessions: make(map[string]*quicSession),
		logger:   options.Logger,
		options:  options,
	}
}
func (d *icmpDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	return nil
}

func (d *icmpDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "0")
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	d.sessionMutex.Lock()

	session, ok := d.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(d.sessions, addr) // session is dead
		ok = false
	}
	if !ok {
		options := &dialer.DialOptions{}
		for _, opt := range opts {
			opt(options)
		}

		var pc net.PacketConn
		if d.ip6 {
			pc, err = icmp_pkg.ListenPacket("ip6:ipv6-icmp", "")
		} else {
			pc, err = icmp_pkg.ListenPacket("ip4:icmp", "")
		}
		if err != nil {
			d.sessionMutex.Unlock()
			return
		}

		id := raddr.Port
		if id == 0 {
			id = rand.New(rand.NewSource(time.Now().UnixNano())).Intn(math.MaxUint16) + 1
			raddr.Port = id
		}
		pc = icmp_pkg.ClientConn(d.ip6, pc, id)

		session, err = d.initSession(ctx, raddr, pc)
		if err != nil {
			d.logger.Error(err)
			pc.Close()
			d.sessionMutex.Unlock()
			return nil, err
		}

		d.sessions[addr] = session
	}
	d.sessionMutex.Unlock()

	conn, err = session.GetConn()
	if err != nil {
		d.sessionMutex.Lock()
		if d.sessions[addr] == session {
			delete(d.sessions, addr)
		}
		session.Close()
		d.sessionMutex.Unlock()
		return nil, err
	}

	return
}

func (d *icmpDialer) initSession(ctx context.Context, addr net.Addr, conn net.PacketConn) (*quicSession, error) {
	quicConfig := &quic.Config{
		KeepAlivePeriod:      d.md.keepAlivePeriod,
		HandshakeIdleTimeout: d.md.handshakeTimeout,
		MaxIdleTimeout:       d.md.maxIdleTimeout,
		Versions: []quic.Version{
			quic.Version1,
			quic.Version2,
		},
	}

	tlsCfg := d.options.TLSConfig
	tlsCfg = tlsCfg.Clone()
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h3", "quic/v1"}
	}

	session, err := quic.DialEarly(ctx, conn, addr, tlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}
	return &quicSession{session: session}, nil
}

// Multiplex implements dialer.Multiplexer interface.
func (d *icmpDialer) Multiplex() bool {
	return true
}
