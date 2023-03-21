package mws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultPath            = "/ws"
	defaultKeepalivePeriod = 15 * time.Second
)

type metadata struct {
	host string
	path string

	handshakeTimeout  time.Duration
	readHeaderTimeout time.Duration
	readBufferSize    int
	writeBufferSize   int
	enableCompression bool

	muxKeepAliveDisabled bool
	muxKeepAliveInterval time.Duration
	muxKeepAliveTimeout  time.Duration
	muxMaxFrameSize      int
	muxMaxReceiveBuffer  int
	muxMaxStreamBuffer   int

	header            http.Header
	keepaliveInterval time.Duration
}

func (d *mwsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host = "host"
		path = "path"

		handshakeTimeout  = "handshakeTimeout"
		readHeaderTimeout = "readHeaderTimeout"
		readBufferSize    = "readBufferSize"
		writeBufferSize   = "writeBufferSize"
		enableCompression = "enableCompression"

		header = "header"

		muxKeepAliveDisabled = "muxKeepAliveDisabled"
		muxKeepAliveInterval = "muxKeepAliveInterval"
		muxKeepAliveTimeout  = "muxKeepAliveTimeout"
		muxMaxFrameSize      = "muxMaxFrameSize"
		muxMaxReceiveBuffer  = "muxMaxReceiveBuffer"
		muxMaxStreamBuffer   = "muxMaxStreamBuffer"
	)

	d.md.host = mdutil.GetString(md, host)

	d.md.path = mdutil.GetString(md, path)
	if d.md.path == "" {
		d.md.path = defaultPath
	}

	d.md.muxKeepAliveDisabled = mdutil.GetBool(md, muxKeepAliveDisabled)
	d.md.muxKeepAliveInterval = mdutil.GetDuration(md, muxKeepAliveInterval)
	d.md.muxKeepAliveTimeout = mdutil.GetDuration(md, muxKeepAliveTimeout)
	d.md.muxMaxFrameSize = mdutil.GetInt(md, muxMaxFrameSize)
	d.md.muxMaxReceiveBuffer = mdutil.GetInt(md, muxMaxReceiveBuffer)
	d.md.muxMaxStreamBuffer = mdutil.GetInt(md, muxMaxStreamBuffer)

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	d.md.readHeaderTimeout = mdutil.GetDuration(md, readHeaderTimeout)
	d.md.readBufferSize = mdutil.GetInt(md, readBufferSize)
	d.md.writeBufferSize = mdutil.GetInt(md, writeBufferSize)
	d.md.enableCompression = mdutil.GetBool(md, enableCompression)

	if m := mdutil.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}

	if mdutil.GetBool(md, "keepalive") {
		d.md.keepaliveInterval = mdutil.GetDuration(md, "ttl", "keepalive.interval")
		if d.md.keepaliveInterval <= 0 {
			d.md.keepaliveInterval = defaultKeepalivePeriod
		}
	}

	return
}
