package http2

import (
	"net/http"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultRealm = "gost"
)

type metadata struct {
	probeResistance      *probeResistance
	header               http.Header
	hash                 string
	authBasicRealm       string
	observerPeriod       time.Duration
	observerResetTraffic bool

	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration
}

func (h *http2Handler) parseMetadata(md mdata.Metadata) error {
	if m := mdutil.GetStringMapString(md, "http.header", "header"); len(m) > 0 {
		hd := http.Header{}
		for k, v := range m {
			hd.Add(k, v)
		}
		h.md.header = hd
	}

	if pr := mdutil.GetString(md, "probeResist", "probe_resist"); pr != "" {
		if ss := strings.SplitN(pr, ":", 2); len(ss) == 2 {
			h.md.probeResistance = &probeResistance{
				Type:  ss[0],
				Value: ss[1],
				Knock: mdutil.GetString(md, "knock"),
			}
		}
	}
	h.md.hash = mdutil.GetString(md, "hash")
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

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
