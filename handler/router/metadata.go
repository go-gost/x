package router

import (
	"time"

	"github.com/go-gost/core/ingress"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

const (
	defaultTTL        = 15 * time.Second
	defaultBufferSize = 1500
)

type metadata struct {
	readTimeout time.Duration
	bufferSize  int

	entryPoint string
	ingress    ingress.Ingress
	sd         sd.SD
	router     router.Router

	observerPeriod       time.Duration
	observerResetTraffic bool

	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration
}

func (h *routerHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	h.md.bufferSize = mdutil.GetInt(md, "router.bufferSize", "bufferSize")
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	h.md.entryPoint = mdutil.GetString(md, "entrypoint")
	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, "ingress"))
	h.md.sd = registry.SDRegistry().Get(mdutil.GetString(md, "sd"))
	h.md.router = registry.RouterRegistry().Get(mdutil.GetString(md, "router"))

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
