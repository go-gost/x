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
	// defaultTTL is the default SD renew interval. Matches the typical
	// TTL used in service discovery backends.
	defaultTTL = 15 * time.Second

	// defaultBufferSize is the default buffer size for reading IP packets
	// and UDP datagrams. 4096 is large enough for most IP packets while
	// keeping memory overhead reasonable.
	defaultBufferSize = 4096

	// defaultCacheExpiration is the default TTL for route and SD caches.
	// 1 second is intentionally short to balance freshness with cache hits
	// for burst traffic.
	defaultCacheExpiration = time.Second
)

// metadata holds the parsed configuration for the router handler.
//
// All fields are populated by parseMetadata during Init. Configuration
// values come from the GOST config file, CLI flags, and environment
// variables — merged by the parser framework.
type metadata struct {
	// readTimeout is the deadline for reading the initial relay protocol
	// handshake from the client connection. The deadline is cleared
	// after the handshake, so it does not affect subsequent data
	// transfer. 0 or negative means no timeout is applied.
	readTimeout time.Duration

	// bufferSize controls the size of the read buffer used in the
	// handleAssociate read loop and handleEntrypoint. Must be at least
	// large enough for a typical IP packet + relay header overhead.
	bufferSize int

	// entryPoint is the UDP address for inter-node packet forwarding.
	// When set, this node binds a UDP socket and participates in the
	// mesh as a peer that can receive forwarded packets.
	entryPoint string

	// ingress is the ingress rule controller. It maps hostnames to
	// router IDs, determining which router should handle which hosts.
	ingress ingress.Ingress

	// sd is the service discovery backend. Used to register connectors
	// and discover peer nodes' addresses.
	// When nil, inter-node forwarding is disabled.
	sd sd.SD

	// sdCacheExpiration controls how long resolved peer addresses are
	// cached before re-querying service discovery.
	sdCacheExpiration time.Duration

	// sdRenewInterval controls how often the SD registration is renewed.
	// Must be at least 1 second; smaller values are clamped to defaultTTL.
	sdRenewInterval time.Duration

	// router is the fallback route resolver. When a router ID is not
	// found in the registry, this fallback is consulted.
	router router.Router

	// routerCacheEnabled enables caching of route lookups. When enabled,
	// the destination IP is used as the cache key.
	routerCacheEnabled bool

	// routerCacheExpiration controls how long cached routes are valid.
	routerCacheExpiration time.Duration

	// observerPeriod controls the interval for reporting traffic stats.
	// Default: 5s. Minimum: 1s.
	observerPeriod time.Duration

	// observerResetTraffic controls whether traffic counters are reset
	// after each observation.
	observerResetTraffic bool

	// limiterRefreshInterval controls how often the cached traffic
	// limiter entries are refreshed.
	limiterRefreshInterval time.Duration

	// limiterCleanupInterval controls how often stale traffic limiter
	// entries are cleaned up.
	limiterCleanupInterval time.Duration
}

// parseMetadata extracts typed configuration values from the metadata
// map and applies defaults.
//
// Key naming conventions:
//   - CamelCase keys (e.g., "readTimeout") are the canonical form.
//   - Dotted keys (e.g., "sd.cache.expiration") represent nested config.
//   - Multiple fallback keys (e.g., "observePeriod", "observer.period",
//     "observer.observePeriod") provide backward compatibility.
func (h *routerHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	h.md.bufferSize = mdutil.GetInt(md, "router.bufferSize", "bufferSize")
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	h.md.entryPoint = mdutil.GetString(md, "entrypoint")
	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, "ingress"))

	h.md.sd = registry.SDRegistry().Get(mdutil.GetString(md, "sd"))
	h.md.sdCacheExpiration = mdutil.GetDuration(md, "sd.cache.expiration")
	if h.md.sdCacheExpiration <= 0 {
		h.md.sdCacheExpiration = defaultCacheExpiration
	}
	h.md.sdRenewInterval = mdutil.GetDuration(md, "sd.renewInterval")
	if h.md.sdRenewInterval < time.Second {
		h.md.sdRenewInterval = defaultTTL
	}

	h.md.router = registry.RouterRegistry().Get(mdutil.GetString(md, "router"))
	h.md.routerCacheEnabled = mdutil.GetBool(md, "router.cache")
	h.md.routerCacheExpiration = mdutil.GetDuration(md, "router.cache.expiration")
	if h.md.routerCacheExpiration <= 0 {
		h.md.routerCacheExpiration = defaultCacheExpiration
	}

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
