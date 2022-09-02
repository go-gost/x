package mws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
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

	l.md.path = mdutil.GetString(md, path)
	if l.md.path == "" {
		l.md.path = defaultPath
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	l.md.readHeaderTimeout = mdutil.GetDuration(md, readHeaderTimeout)
	l.md.readBufferSize = mdutil.GetInt(md, readBufferSize)
	l.md.writeBufferSize = mdutil.GetInt(md, writeBufferSize)
	l.md.enableCompression = mdutil.GetBool(md, enableCompression)

	l.md.muxKeepAliveDisabled = mdutil.GetBool(md, muxKeepAliveDisabled)
	l.md.muxKeepAliveInterval = mdutil.GetDuration(md, muxKeepAliveInterval)
	l.md.muxKeepAliveTimeout = mdutil.GetDuration(md, muxKeepAliveTimeout)
	l.md.muxMaxFrameSize = mdutil.GetInt(md, muxMaxFrameSize)
	l.md.muxMaxReceiveBuffer = mdutil.GetInt(md, muxMaxReceiveBuffer)
	l.md.muxMaxStreamBuffer = mdutil.GetInt(md, muxMaxStreamBuffer)

	if mm := mdutil.GetStringMapString(md, header); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}
	return
}
