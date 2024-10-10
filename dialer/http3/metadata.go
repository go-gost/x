package http3

import (
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultAuthorizePath = "/authorize"
	defaultPushPath      = "/push"
	defaultPullPath      = "/pull"
)

type metadata struct {
	authorizePath string
	pushPath      string
	pullPath      string
	host          string

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
}

func (d *http3Dialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepalive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"
	)

	d.md.authorizePath = mdutil.GetString(md, "pht.authorizePath", "authorizePath")
	if !strings.HasPrefix(d.md.authorizePath, "/") {
		d.md.authorizePath = defaultAuthorizePath
	}
	d.md.pushPath = mdutil.GetString(md, "pht.pushPath", "pushPath")
	if !strings.HasPrefix(d.md.pushPath, "/") {
		d.md.pushPath = defaultPushPath
	}
	d.md.pullPath = mdutil.GetString(md, "pht.pullPath", "pullPath")
	if !strings.HasPrefix(d.md.pullPath, "/") {
		d.md.pullPath = defaultPullPath
	}

	d.md.host = mdutil.GetString(md, "host")
	if md == nil || !md.IsExists(keepAlive) || mdutil.GetBool(md, keepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	d.md.maxStreams = mdutil.GetInt(md, maxStreams)

	return
}
