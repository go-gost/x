package dns

import (
	"net"
	"time"

	mdata "github.com/go-gost/core/metadata"
)

const (
	defaultBufferSize = 1024
)

type metadata struct {
	readTimeout time.Duration
	ttl         time.Duration
	timeout     time.Duration
	clientIP    net.IP
	// nameservers
	dns []string
}

func (h *dnsHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout = "readTimeout"
		ttl         = "ttl"
		timeout     = "timeout"
		clientIP    = "clientIP"
		dns         = "dns"
	)

	h.md.readTimeout = mdata.GetDuration(md, readTimeout)
	h.md.ttl = mdata.GetDuration(md, ttl)
	h.md.timeout = mdata.GetDuration(md, timeout)
	if h.md.timeout <= 0 {
		h.md.timeout = 5 * time.Second
	}
	sip := mdata.GetString(md, clientIP)
	if sip != "" {
		h.md.clientIP = net.ParseIP(sip)
	}
	h.md.dns = mdata.GetStrings(md, dns)

	return
}
