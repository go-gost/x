package masque

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	// defaultBufferSize is the default UDP relay buffer size in bytes.
	defaultBufferSize = 4096
	// defaultRealm is the default HTTP Basic authentication realm for proxy auth.
	defaultRealm = "gost"
)

// metadata holds parsed configuration values for the MASQUE handler.
// Values are extracted from the generic metadata map via parseMetadata.
type metadata struct {
	// hash defines the hash source for load-balancing selector.
	// When set to "host", the target address is used as the hash input
	// for consistent routing through chain hops.
	hash string
	// bufferSize is the UDP relay buffer size in bytes for datagram forwarding.
	bufferSize int
	// authBasicRealm is the realm string sent in Proxy-Authenticate challenges.
	authBasicRealm string
	// idleTimeout is the read timeout for TCP connections during bidirectional relay.
	// After this duration with no data, the relay is terminated.
	idleTimeout time.Duration

	// observerPeriod is the interval between observer stats collection cycles.
	observerPeriod time.Duration
	// observerResetTraffic controls whether per-client traffic counters are
	// reset to zero after each observer report.
	observerResetTraffic bool
	// limiterRefreshInterval controls how often the cached traffic limiter
	// refreshes its limits from the global limiter source.
	limiterRefreshInterval time.Duration
	// limiterCleanupInterval controls how often the cached traffic limiter
	// removes stale cached entries for disconnected clients.
	limiterCleanupInterval time.Duration
}

// parseMetadata extracts typed configuration values from the generic metadata map.
// Metadata keys support multiple fallback names for compatibility (e.g., "bufferSize"
// and "udp.bufferSize"). Duration values accept both integer (seconds) and string
// (Go duration format like "5s") inputs.
func (h *masqueHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.hash = mdutil.GetString(md, "hash")

	h.md.bufferSize = mdutil.GetInt(md, "bufferSize", "udp.bufferSize")
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	h.md.authBasicRealm = mdutil.GetString(md, "authBasicRealm")

	h.md.observerPeriod = mdutil.GetDuration(md, "observePeriod", "observer.period", "observer.observePeriod")
	if h.md.observerPeriod == 0 {
		h.md.observerPeriod = 5 * time.Second
	}
	if h.md.observerPeriod < time.Second {
		h.md.observerPeriod = time.Second
	}

	h.md.observerResetTraffic = mdutil.GetBool(md, "observer.resetTraffic")
	h.md.idleTimeout = mdutil.GetDuration(md, "readTimeout", "read.timeout", "idleTimeout")

	h.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	h.md.limiterCleanupInterval = mdutil.GetDuration(md, "limiter.cleanupInterval")

	return nil
}
