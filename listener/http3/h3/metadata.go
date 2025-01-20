package h3

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
	defaultBacklog       = 128
)

type metadata struct {
	authorizePath string
	pushPath      string
	pullPath      string
	backlog       int

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
}

func (l *http3Listener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepalive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"

		backlog = "backlog"
	)

	l.md.authorizePath = mdutil.GetString(md, "pht.authorizePath", "authorizePath")
	if !strings.HasPrefix(l.md.authorizePath, "/") {
		l.md.authorizePath = defaultAuthorizePath
	}
	l.md.pushPath = mdutil.GetString(md, "pht.pushPath", "pushPath")
	if !strings.HasPrefix(l.md.pushPath, "/") {
		l.md.pushPath = defaultPushPath
	}
	l.md.pullPath = mdutil.GetString(md, "pht.pullPath", "pullPath")
	if !strings.HasPrefix(l.md.pullPath, "/") {
		l.md.pullPath = defaultPullPath
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if mdutil.GetBool(md, keepAlive) {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	l.md.maxStreams = mdutil.GetInt(md, maxStreams)

	return
}
