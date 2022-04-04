package mws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultPath = "/ws"
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

	header    http.Header
	keepAlive time.Duration
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

		header    = "header"
		keepAlive = "keepAlive"

		muxKeepAliveDisabled = "muxKeepAliveDisabled"
		muxKeepAliveInterval = "muxKeepAliveInterval"
		muxKeepAliveTimeout  = "muxKeepAliveTimeout"
		muxMaxFrameSize      = "muxMaxFrameSize"
		muxMaxReceiveBuffer  = "muxMaxReceiveBuffer"
		muxMaxStreamBuffer   = "muxMaxStreamBuffer"
	)

	d.md.host = mdx.GetString(md, host)

	d.md.path = mdx.GetString(md, path)
	if d.md.path == "" {
		d.md.path = defaultPath
	}

	d.md.muxKeepAliveDisabled = mdx.GetBool(md, muxKeepAliveDisabled)
	d.md.muxKeepAliveInterval = mdx.GetDuration(md, muxKeepAliveInterval)
	d.md.muxKeepAliveTimeout = mdx.GetDuration(md, muxKeepAliveTimeout)
	d.md.muxMaxFrameSize = mdx.GetInt(md, muxMaxFrameSize)
	d.md.muxMaxReceiveBuffer = mdx.GetInt(md, muxMaxReceiveBuffer)
	d.md.muxMaxStreamBuffer = mdx.GetInt(md, muxMaxStreamBuffer)

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.readHeaderTimeout = mdx.GetDuration(md, readHeaderTimeout)
	d.md.readBufferSize = mdx.GetInt(md, readBufferSize)
	d.md.writeBufferSize = mdx.GetInt(md, writeBufferSize)
	d.md.enableCompression = mdx.GetBool(md, enableCompression)

	if m := mdx.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}
	d.md.keepAlive = mdx.GetDuration(md, keepAlive)

	return
}
