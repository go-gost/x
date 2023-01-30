package relay

import (
	"fmt"
	"net"
	"strconv"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	mdx "github.com/go-gost/x/metadata"
)

type tcpListener struct {
	addr    net.Addr
	session *mux.Session
	logger  logger.Logger
}

func (p *tcpListener) Accept() (net.Conn, error) {
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

func (p *tcpListener) getPeerConn(conn net.Conn) (net.Conn, error) {
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

	cn := &bindConn{
		Conn:       conn,
		localAddr:  p.addr,
		remoteAddr: raddr,
	}
	if host != "" {
		cn.md = mdx.NewMetadata(map[string]any{"host": host})
	}
	return cn, nil
}

func (p *tcpListener) Addr() net.Addr {
	return p.addr
}

func (p *tcpListener) Close() error {
	return p.session.Close()
}
