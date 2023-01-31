package http2

import (
	"net/http"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultRealm = "gost"
)

type metadata struct {
	probeResistance *probeResistance
	header          http.Header
	hash            string
	authBasicRealm  string
}

func (h *http2Handler) parseMetadata(md mdata.Metadata) error {
	const (
		header          = "header"
		probeResistKey  = "probeResistance"
		probeResistKeyX = "probe_resist"
		knock           = "knock"
		hash            = "hash"
		authBasicRealm  = "authBasicRealm"
	)

	if m := mdutil.GetStringMapString(md, header); len(m) > 0 {
		hd := http.Header{}
		for k, v := range m {
			hd.Add(k, v)
		}
		h.md.header = hd
	}

	pr := mdutil.GetString(md, probeResistKey)
	if pr == "" {
		pr = mdutil.GetString(md, probeResistKeyX)
	}
	if pr != "" {
		if ss := strings.SplitN(pr, ":", 2); len(ss) == 2 {
			h.md.probeResistance = &probeResistance{
				Type:  ss[0],
				Value: ss[1],
				Knock: mdutil.GetString(md, knock),
			}
		}
	}
	h.md.hash = mdutil.GetString(md, hash)
	h.md.authBasicRealm = mdutil.GetString(md, authBasicRealm)

	return nil
}

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
