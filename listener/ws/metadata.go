package ws

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

	handshakeTimeout  time.Duration
	readHeaderTimeout time.Duration
	readBufferSize    int
	writeBufferSize   int
	enableCompression bool

	header http.Header
}

func (l *wsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		path    = "path"
		backlog = "backlog"

		handshakeTimeout  = "handshakeTimeout"
		readHeaderTimeout = "readHeaderTimeout"
		readBufferSize    = "readBufferSize"
		writeBufferSize   = "writeBufferSize"
		enableCompression = "enableCompression"

		header = "header"
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

	if mm := mdutil.GetStringMapString(md, header); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}
	return
}
