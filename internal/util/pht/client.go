package pht

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-gost/core/logger"
	"github.com/rs/xid"
)

type Client struct {
	Host       string
	Client     *http.Client
	PushPath   string
	PullPath   string
	TLSEnabled bool
	Header     http.Header
	Logger     logger.Logger
}

func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		c.Logger.Error(err)
		return nil, err
	}

	if c.Host != "" {
		addr = net.JoinHostPort(c.Host, strconv.Itoa(raddr.Port))
	}

	connCtx, cancel := context.WithCancel(ctx)
	cid := xid.New().String()
	cn := &clientConn{
		client:     c.Client,
		header:     c.Header,
		rxc:        make(chan []byte, 128),
		closed:     make(chan struct{}),
		ctx:        connCtx,
		cancel:     cancel,
		localAddr:  &net.TCPAddr{},
		remoteAddr: raddr,
		logger:     c.Logger,
	}

	scheme := "http"
	if c.TLSEnabled {
		scheme = "https"
	}
	cn.pushURL = fmt.Sprintf("%s://%s%s?token=%s", scheme, addr, c.PushPath, cid)
	cn.pullURL = fmt.Sprintf("%s://%s%s?token=%s", scheme, addr, c.PullPath, cid)

	go cn.readLoop()

	return cn, nil
}
