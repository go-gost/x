package tunnel

import (
	"fmt"
	"net"
	"strconv"

	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	mdx "github.com/go-gost/x/metadata"
)

type bindListener struct {
	network string
	addr    net.Addr
	session *mux.Session
	logger  logger.Logger
}

func (p *bindListener) Accept() (net.Conn, error) {
	cc, err := p.session.Accept()
	if err != nil {
		return nil, err
	}

	conn, err := p.getPeerConn(cc)
	if err != nil {
		cc.Close()
		p.logger.Errorf("get peer failed: %s", err)
		return nil, err
	}

	return conn, nil
}

func (p *bindListener) getPeerConn(conn net.Conn) (net.Conn, error) {
	// second reply, peer connected
	resp := relay.Response{}
	if _, err := resp.ReadFrom(conn); err != nil {
		return nil, err
	}

	if resp.Status != relay.StatusOK {
		err := fmt.Errorf("peer connect failed")
		return nil, err
	}

	var address, host string
	// the first addr is the client address, the optional second addr is the target host address.
	for _, f := range resp.Features {
		if f.Type() == relay.FeatureAddr {
			if fa, ok := f.(*relay.AddrFeature); ok {
				v := net.JoinHostPort(fa.Host, strconv.Itoa(int(fa.Port)))
				if address != "" {
					host = v
				} else {
					address = v
				}
			}
		}
	}

	raddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	var md mdata.Metadata
	if host != "" {
		md = mdx.NewMetadata(map[string]any{"host": host})
	}

	if p.network == "udp" {
		return &bindUDPConn{
			Conn:       conn,
			localAddr:  p.addr,
			remoteAddr: raddr,
			md:         md,
		}, nil
	}

	cn := &bindConn{
		Conn:       conn,
		localAddr:  p.addr,
		remoteAddr: raddr,
		md:         md,
	}
	return cn, nil
}

func (p *bindListener) Addr() net.Addr {
	return p.addr
}

func (p *bindListener) Close() error {
	return p.session.Close()
}
