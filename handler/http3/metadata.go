package http3

import (
	"net/http"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	probeResistance *probeResistance
	header          http.Header
	hash            string
}

func (h *http3Handler) parseMetadata(md mdata.Metadata) error {
	const (
		header          = "header"
		probeResistKey  = "probeResistance"
		probeResistKeyX = "probe_resist"
		knock           = "knock"
		hash            = "hash"
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

	return nil
}

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
