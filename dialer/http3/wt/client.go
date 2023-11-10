package wt

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-gost/core/logger"
	wt_util "github.com/go-gost/x/internal/util/wt"
	wt "github.com/quic-go/webtransport-go"
)

type Client struct {
	host    string
	path    string
	header  http.Header
	dialer  *wt.Dialer
	session *wt.Session
	log     logger.Logger
}

func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	ok := false
	if c.session != nil {
		select {
		case <-c.session.Context().Done():
		default:
			ok = true
		}
	}
	if !ok {
		url := url.URL{
			Scheme: "https",
			Host:   c.host,
			Path:   c.path,
		}
		resp, session, err := c.dialer.Dial(ctx, url.String(), c.header)
		if err != nil {
			return nil, err
		}

		if c.log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			c.log.Trace(string(dump))
		}

		c.session = session
	}

	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, err
	}

	return wt_util.Conn(c.session, stream), nil
}
