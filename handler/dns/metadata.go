package dns

import (
	"net"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	// defaultTimeout is the fallback timeout for DNS exchanges.
	defaultTimeout = 5 * time.Second
	// defaultBufferSize is the fallback buffer size for DNS message I/O.
	defaultBufferSize = 4096
)

// metadata holds parsed DNS handler configuration.
type metadata struct {
	// readTimeout is the deadline for reading DNS query and writing DNS
	// response on the client connection. Each DNS exchange (one query +
	// one response) must complete within this window.
	// Default: 0 (no timeout set by handler — DNS upstream timeout is
	// controlled separately by the "timeout" field).
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
