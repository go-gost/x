package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/go-shadowsocks2/core"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBufferSize = 4096
)

type metadata struct {
	key           string
	// readTimeout is the deadline for reading a single UDP datagram from
	// the client. Since UDP is connectionless, this timeout applies to
	// each individual datagram read. Default: 1 minute (longer than the
	// typical 15s used by TCP handlers to accommodate the stateless
	// nature of UDP).
	readTimeout   time.Duration
	udpBufferSize int

	users []core.UserConfig
}

func (h *ssuHandler) parseMetadata(md mdata.Metadata) (err error) {

	h.md.key = mdutil.GetString(md, "key")
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout == 0 {
		h.md.readTimeout = time.Minute // Default read timeout
	}
	h.md.udpBufferSize = mdutil.GetInt(md, "udpBufferSize", "udp.bufferSize")

	usersMap := mdutil.GetStringMapString(md, "users")
	for name, pass := range usersMap {
		h.md.users = append(h.md.users, core.UserConfig{
			Name:     name,
			Password: pass,
		})
	}

	return
}
