package http

import (
	"net/http"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultRealm      = "gost"
	defaultProxyAgent = "gost/3.0"
)

type metadata struct {
	probeResistance *probeResistance
	enableUDP       bool
	header          http.Header
	hash            string
	authBasicRealm  string
	observePeriod   time.Duration
	proxyAgent      string
}

func (h *httpHandler) parseMetadata(md mdata.Metadata) error {
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
	h.md.enableUDP = mdutil.GetBool(md, "udp")
	h.md.hash = mdutil.GetString(md, "hash")
	h.md.authBasicRealm = mdutil.GetString(md, "authBasicRealm")

	h.md.observePeriod = mdutil.GetDuration(md, "observePeriod")

	h.md.proxyAgent = mdutil.GetString(md, "http.proxyAgent", "proxyAgent")
	if h.md.proxyAgent == "" {
		h.md.proxyAgent = defaultProxyAgent
	}

	return nil
}

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
