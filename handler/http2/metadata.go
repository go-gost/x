package http2

import (
	"net/http"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	probeResistance *probeResistance
	header          http.Header
}

func (h *http2Handler) parseMetadata(md mdata.Metadata) error {
	const (
		header          = "header"
		probeResistKey  = "probeResistance"
		probeResistKeyX = "probe_resist"
		knock           = "knock"
	)

	if m := mdx.GetStringMapString(md, header); len(m) > 0 {
		hd := http.Header{}
		for k, v := range m {
			hd.Add(k, v)
		}
		h.md.header = hd
	}

	pr := mdx.GetString(md, probeResistKey)
	if pr == "" {
		pr = mdx.GetString(md, probeResistKeyX)
	}
	if pr != "" {
		if ss := strings.SplitN(pr, ":", 2); len(ss) == 2 {
			h.md.probeResistance = &probeResistance{
				Type:  ss[0],
				Value: ss[1],
				Knock: mdx.GetString(md, knock),
			}
		}
	}

	return nil
}

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
