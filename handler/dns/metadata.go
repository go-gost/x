package dns

import (
	"net"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultTimeout    = 5 * time.Second
	defaultBufferSize = 1024
)

type metadata struct {
	readTimeout time.Duration
	ttl         time.Duration
	timeout     time.Duration
	clientIP    net.IP
	// nameservers
	dns        []string
	bufferSize int
	async      bool
}

func (h *dnsHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout = "readTimeout"
		ttl         = "ttl"
		timeout     = "timeout"
		clientIP    = "clientIP"
		dns         = "dns"
		bufferSize  = "bufferSize"
		async       = "async"
	)

	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	h.md.ttl = mdutil.GetDuration(md, ttl)
	h.md.timeout = mdutil.GetDuration(md, timeout)
	if h.md.timeout <= 0 {
		h.md.timeout = defaultTimeout
	}
	sip := mdutil.GetString(md, clientIP)
	if sip != "" {
		h.md.clientIP = net.ParseIP(sip)
	}
	for _, v := range strings.Split(mdutil.GetString(md, dns), ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		h.md.dns = append(h.md.dns, v)
	}

	h.md.bufferSize = mdutil.GetInt(md, bufferSize)
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}
	h.md.async = mdutil.GetBool(md, async)

	return
}
