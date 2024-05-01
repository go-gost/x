package icmp

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	AirSeqCount = 8
	BufQueueLen = 1024
)

type clientConn2 struct {
	net.PacketConn
	raddr    *net.UDPAddr
	bufQueue chan []byte
	seq      uint32
	peerSeq  uint32
	cancel   context.CancelFunc
	ctx      context.Context
}

func ClientConn2(conn net.PacketConn, raddr *net.UDPAddr) net.PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &clientConn2{
		PacketConn: conn,
		raddr:      raddr,
		cancel:     cancel,
		bufQueue:   make(chan []byte, BufQueueLen),
		ctx:        ctx,
	}
	c.PacketConn.SetReadDeadline(time.Now().Add(time.Second * 10))
	c.readDaemon(ctx)
	return c
}

func (c *clientConn2) Close() error {
	c.cancel()
	return c.PacketConn.Close()
}

func (c *clientConn2) readDaemon(ctx context.Context) {
	buf := bufpool.Get(readBufferSize)
	defer bufpool.Put(buf)
	defer c.cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// keepalive check
		for c.seq-c.peerSeq < AirSeqCount {
			if _, err := c.WriteTo(nil, c.raddr); err != nil {
				logger.Default().Error(err)
				return
			}
		}

		// read pkg
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			logger.Default().Error(err)
			return
		}
		v, ok := addr.(*net.IPAddr)
		if !ok {
			continue
		}
		if !v.IP.Equal(c.raddr.IP) {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			// in fact, pk from icmp conn should always match icmp format
			// logger.Default().Error("icmp: parse message %v", err)
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok || m.Type != ipv4.ICMPTypeEchoReply {
			// logger.Default().Warnf("icmp: invalid type %s (discarded)", m.Type)
			continue // discard
		}
		if echo.ID != c.raddr.Port {
			// logger.Default().Warnf("icmp: id mismatch got %d, should be %d (discarded)", echo.ID, c.id)
			continue
		}

		// there is only one goroutine to read from the conn, so no need to lock or atomic
		if uint32(echo.Seq) > c.peerSeq {
			c.peerSeq = uint32(echo.Seq)
		}

		msg := message{}
		if _, err := msg.Decode(echo.Data); err != nil {
			logger.Default().Warn(err)
			continue
		}

		if msg.flags&FlagKeepAlive > 0 {
			continue
		}

		if msg.flags&FlagAck == 0 {
			// logger.Default().Warn("icmp: invalid message (discarded)")
			continue
		}

		// if full, drop packet
		select {
		case c.bufQueue <- msg.data:
		default:
		}
	}
}

func (c *clientConn2) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case buf := <-c.bufQueue:
		n = copy(b, buf)
		return n, c.raddr, nil
	}
}

func (c *clientConn2) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// logger.Default().Infof("icmp: write to: %v %d", addr, len(b))
	switch v := addr.(type) {
	case *net.UDPAddr:
		addr = &net.IPAddr{IP: v.IP}
	}

	buf := bufpool.Get(writeBufferSize)
	defer bufpool.Put(buf)

	msg := message{
		data: b,
	}
	if len(b) == 0 {
		msg.flags |= FlagKeepAlive
	}
	nn, err := msg.Encode(buf)
	if err != nil {
		return
	}

	echo := icmp.Echo{
		ID:   c.raddr.Port,
		Seq:  int(atomic.AddUint32(&c.seq, 1)),
		Data: buf[:nn],
	}
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &echo,
	}
	wb, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(wb, addr)
	n = len(b)
	return
}

type client struct {
	id  uint16
	seq chan uint32
}

type serverConn2 struct {
	net.PacketConn
	// it's bad to create 65535 channels, so just turns to use sync.Map
	clients sync.Map
}

func ServerConn2(conn net.PacketConn) net.PacketConn {
	return &serverConn2{
		PacketConn: conn,
	}
}

func (c *serverConn2) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := bufpool.Get(readBufferSize)
	defer bufpool.Put(buf)

	for {
		n, addr, err = c.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}

		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			// logger.Default().Error("icmp: parse message %v", err)
			return 0, addr, err
		}

		echo, ok := m.Body.(*icmp.Echo)
		if !ok || m.Type != ipv4.ICMPTypeEcho || echo.ID <= 0 {
			// logger.Default().Warnf("icmp: invalid type %s (discarded)", m.Type)
			continue
		}

		cl, ok := c.clients.Load(echo.ID)
		if !ok {
			cl, _ = c.clients.LoadOrStore(echo.ID, &client{id: uint16(echo.ID), seq: make(chan uint32, AirSeqCount)})
		}
		seqC := cl.(*client).seq

	ENQUEUE:
		select {
		case seqC <- uint32(echo.Seq):
		default:
			for {
				<-seqC
				select {
				case seqC <- uint32(echo.Seq):
					break ENQUEUE
				default:
				}
			}
		}

		msg := message{}
		if _, err := msg.Decode(echo.Data); err != nil {
			continue
		}

		if msg.flags&FlagKeepAlive > 0 {
			continue
		}

		if msg.flags&FlagAck > 0 {
			continue
		}

		n = copy(b, msg.data)

		if v, ok := addr.(*net.IPAddr); ok {
			addr = &net.UDPAddr{
				IP:   v.IP,
				Port: echo.ID,
			}
		}
		break
	}

	// logger.Default().Infof("icmp: read from: %v %d", addr, n)

	return
}

func (c *serverConn2) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// logger.Default().Infof("icmp: write to: %v %d", addr, len(b))
	var id int
	switch v := addr.(type) {
	case *net.UDPAddr:
		addr = &net.IPAddr{IP: v.IP}
		id = v.Port
	}

	if id <= 0 || id > math.MaxUint16 {
		err = fmt.Errorf("icmp: invalid message id %v", addr)
		return
	}

	buf := bufpool.Get(writeBufferSize)
	defer bufpool.Put(buf)

	msg := message{
		flags: FlagAck,
		data:  b,
	}
	nn, err := msg.Encode(buf)
	if err != nil {
		return
	}

	cl, ok := c.clients.Load(id)
	if !ok {
		err = fmt.Errorf("icmp: invalid message id %v", addr)
		return
	}
	echo := icmp.Echo{
		ID:   id,
		Seq:  int(<-cl.(*client).seq),
		Data: buf[:nn],
	}
	m := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &echo,
	}
	wb, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(wb, addr)
	n = len(b)
	return
}
