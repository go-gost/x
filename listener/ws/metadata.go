package ws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
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
	header            http.Header

	mptcp bool
}

func (l *wsListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.path = mdutil.GetString(md, "ws.path", "path")
	if l.md.path == "" {
		l.md.path = defaultPath
	}

	l.md.backlog = mdutil.GetInt(md, "ws.backlog", "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.handshakeTimeout = mdutil.GetDuration(md, "ws.handshakeTimeout", "handshakeTimeout")
	l.md.readHeaderTimeout = mdutil.GetDuration(md, "ws.readHeaderTimeout", "readHeaderTimeout")
	l.md.readBufferSize = mdutil.GetInt(md, "ws.readBufferSize", "readBufferSize")
	l.md.writeBufferSize = mdutil.GetInt(md, "ws.writeBufferSize", "writeBufferSize")
	l.md.enableCompression = mdutil.GetBool(md, "ws.enableCompression", "enableCompression")

	if mm := mdutil.GetStringMapString(md, "ws.header", "header"); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}

	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
