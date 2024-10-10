package wt

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultPath            = "/wt"
	defaultKeepalivePeriod = 15 * time.Second
)

type metadata struct {
	host   string
	path   string
	header http.Header

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
}

func (d *wtDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepalive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"
	)

	d.md.host = mdutil.GetString(md, "wt.host", "host")
	d.md.path = mdutil.GetString(md, "wt.path", "path")
	if d.md.path == "" {
		d.md.path = defaultPath
	}

	if md == nil || !md.IsExists(keepAlive) || mdutil.GetBool(md, keepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	d.md.maxStreams = mdutil.GetInt(md, maxStreams)

	if m := mdutil.GetStringMapString(md, "wt.header", "header"); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}

	return
}
