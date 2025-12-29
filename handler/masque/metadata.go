package masque

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBufferSize = 4096
	defaultRealm      = "gost"
)

type metadata struct {
	hash           string
	bufferSize     int
	authBasicRealm string

	observerPeriod         time.Duration
	observerResetTraffic   bool
	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration
}

func (h *masqueHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.hash = mdutil.GetString(md, "hash")

	h.md.bufferSize = mdutil.GetInt(md, "bufferSize", "udp.bufferSize")
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	h.md.authBasicRealm = mdutil.GetString(md, "authBasicRealm")

	h.md.observerPeriod = mdutil.GetDuration(md, "observePeriod", "observer.period", "observer.observePeriod")
	if h.md.observerPeriod == 0 {
		h.md.observerPeriod = 5 * time.Second
	}
	if h.md.observerPeriod < time.Second {
		h.md.observerPeriod = time.Second
	}

	h.md.observerResetTraffic = mdutil.GetBool(md, "observer.resetTraffic")
	h.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	h.md.limiterCleanupInterval = mdutil.GetDuration(md, "limiter.cleanupInterval")

	return nil
}
