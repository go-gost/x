package mws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultPath    = "/ws"
	defaultBacklog = 128
)

type metadata struct {
	path    string
	backlog int
	header  http.Header

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
}

func (l *mwsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		path    = "path"
		backlog = "backlog"
		header  = "header"

		handshakeTimeout  = "handshakeTimeout"
		readHeaderTimeout = "readHeaderTimeout"
		readBufferSize    = "readBufferSize"
		writeBufferSize   = "writeBufferSize"
		enableCompression = "enableCompression"

		muxKeepAliveDisabled = "muxKeepAliveDisabled"
		muxKeepAliveInterval = "muxKeepAliveInterval"
		muxKeepAliveTimeout  = "muxKeepAliveTimeout"
		muxMaxFrameSize      = "muxMaxFrameSize"
		muxMaxReceiveBuffer  = "muxMaxReceiveBuffer"
		muxMaxStreamBuffer   = "muxMaxStreamBuffer"
	)

	l.md.path = mdx.GetString(md, path)
	if l.md.path == "" {
		l.md.path = defaultPath
	}

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	l.md.readHeaderTimeout = mdx.GetDuration(md, readHeaderTimeout)
	l.md.readBufferSize = mdx.GetInt(md, readBufferSize)
	l.md.writeBufferSize = mdx.GetInt(md, writeBufferSize)
	l.md.enableCompression = mdx.GetBool(md, enableCompression)

	l.md.muxKeepAliveDisabled = mdx.GetBool(md, muxKeepAliveDisabled)
	l.md.muxKeepAliveInterval = mdx.GetDuration(md, muxKeepAliveInterval)
	l.md.muxKeepAliveTimeout = mdx.GetDuration(md, muxKeepAliveTimeout)
	l.md.muxMaxFrameSize = mdx.GetInt(md, muxMaxFrameSize)
	l.md.muxMaxReceiveBuffer = mdx.GetInt(md, muxMaxReceiveBuffer)
	l.md.muxMaxStreamBuffer = mdx.GetInt(md, muxMaxStreamBuffer)

	if mm := mdx.GetStringMapString(md, header); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}
	return
}
