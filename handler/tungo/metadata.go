package tungo

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	udpTimeout time.Duration

	sniffing                bool
	sniffingUDP                bool
	sniffingTimeout         time.Duration
	sniffingResponseTimeout time.Duration
	sniffingFallback        bool

	observerPeriod       time.Duration
	observerResetTraffic bool

	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration
}

func (h *tungoHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.udpTimeout = mdutil.GetDuration(md, "udpTimeout")

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingUDP = mdutil.GetBool(md, "sniffing.udp")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")
	h.md.sniffingResponseTimeout = mdutil.GetDuration(md, "sniffing.responseTimeout")
	h.md.sniffingFallback = mdutil.GetBool(md, "sniffing.fallback")

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

	return
}
