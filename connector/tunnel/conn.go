package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/go-gost/core/common/bufpool"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	xrelay "github.com/go-gost/x/internal/util/relay"
)

type udpConn struct {
	net.Conn
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	var bb [2]byte
	_, err = io.ReadFull(c.Conn, bb[:])
	if err != nil {
		return
	}

	dlen := int(binary.BigEndian.Uint16(bb[:]))
	if len(b) >= dlen {
		return io.ReadFull(c.Conn, b[:dlen])
	}

	buf := bufpool.Get(dlen)
	defer bufpool.Put(buf)
	_, err = io.ReadFull(c.Conn, buf)
	n = copy(b, buf)

	return
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	if len(b) > math.MaxUint16 {
		err = errors.New("write: data maximum exceeded")
		return
	}

	n = len(b)

	var bb [2]byte
	binary.BigEndian.PutUint16(bb[:], uint16(len(b)))
	_, err = c.Conn.Write(bb[:])
	if err != nil {
		return
	}
	return c.Conn.Write(b)
}

func readResponse(r io.Reader) (err error) {
	resp := relay.Response{}
	_, err = resp.ReadFrom(r)
	if err != nil {
		return
	}

	if resp.Version != relay.Version1 {
		err = relay.ErrBadVersion
		return
	}

	if resp.Status != relay.StatusOK {
		err = fmt.Errorf("%d %s", resp.Status, xrelay.StatusText(resp.Status))
		return
	}
	return nil
}

type bindConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
	md         mdata.Metadata
}

func (c *bindConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *bindConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Metadata implements metadata.Metadatable interface.
func (c *bindConn) Metadata() mdata.Metadata {
	return c.md
}

type bindUDPConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
	md         mdata.Metadata
}

func (c *bindUDPConn) Read(b []byte) (n int, err error) {
	// 2-byte data length header
	var bh [2]byte
	_, err = io.ReadFull(c.Conn, bh[:])
	if err != nil {
		return
	}

	dlen := int(binary.BigEndian.Uint16(bh[:]))
	if len(b) >= dlen {
		n, err = io.ReadFull(c.Conn, b[:dlen])
		return
	}

	buf := bufpool.Get(dlen)
	defer bufpool.Put(buf)

	_, err = io.ReadFull(c.Conn, buf)
	n = copy(b, buf)

	return
}

func (c *bindUDPConn) Write(b []byte) (n int, err error) {
	if len(b) > math.MaxUint16 {
		err = errors.New("write: data maximum exceeded")
		return
	}

	buf := bufpool.Get(len(b) + 2)
	defer bufpool.Put(buf)

	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	n = copy(buf[2:], b)

	return c.Conn.Write(buf)
}

func (c *bindUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	addr = c.remoteAddr
	n, err = c.Read(b)
	return
}

func (c *bindUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Write(b)
}

func (c *bindUDPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *bindUDPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Metadata implements metadata.Metadatable interface.
func (c *bindUDPConn) Metadata() mdata.Metadata {
	return c.md
}

type bindAddr struct {
	network string
	addr    string
}

func (p *bindAddr) Network() string {
	return p.network
}

func (p *bindAddr) String() string {
	return p.addr
}
