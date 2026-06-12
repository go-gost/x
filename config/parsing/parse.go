// Package parsing converts user-facing configuration structs into registered
// runtime components. Each sub-package (service, hop, chain, auth, …) owns the
// parsing logic for its corresponding core interface.
//
// Metadata keys defined below bridge the gap between named config fields and
// generic key-value metadata. When a value is not represented by an explicit
// field on a config struct it flows through the metadata system instead and
// these keys are used to look it up at component Init time.
package parsing

const (
	// MDKeyProxyProtocol sets the HAProxy proxy-protocol version on a listener.
	MDKeyProxyProtocol = "proxyProtocol"

	// MDKeyInterface binds the outbound connection to a specific network interface.
	MDKeyInterface = "interface"

	// MDKeySoMark sets the SO_MARK socket option on outbound connections.
	MDKeySoMark = "so_mark"

	// MDKeyHash selects the hash source used by hash-based selectors.
	MDKeyHash = "hash"

	// MDKeyPreUp is a shell command executed when a service starts listening.
	MDKeyPreUp = "preUp"

	// MDKeyPreDown is a shell command executed immediately before a service
	// stops listening.
	MDKeyPreDown = "preDown"

	// MDKeyPostUp is a shell command executed after a service has successfully
	// started listening.
	MDKeyPostUp = "postUp"

	// MDKeyPostDown is a shell command executed after a service has stopped
	// listening.
	MDKeyPostDown = "postDown"

	// MDKeyIgnoreChain disables chain routing for a service. When set the
	// listener/handler will not prepend a chain, which is useful for services
	// that handle routing themselves (e.g. DNS, TUN).
	MDKeyIgnoreChain = "ignoreChain"

	// MDKeyEnableStats enables per-service connection statistics collection.
	MDKeyEnableStats = "enableStats"

	// MDKeyRecorderDirection toggles whether traffic direction (client→server or
	// server→client) is recorded alongside the payload.
	MDKeyRecorderDirection = "direction"

	// MDKeyRecorderTimestampFormat sets the timestamp layout used in recorder
	// output (Go time.Format layout).
	MDKeyRecorderTimestampFormat = "timeStampFormat"

	// MDKeyRecorderHexdump enables hexadecimal dump output in recorders.
	MDKeyRecorderHexdump = "hexdump"

	// MDKeyRecorderHTTPBody enables capturing the HTTP request/response body in
	// HTTP-based recorders.
	MDKeyRecorderHTTPBody = "http.body"

	// MDKeyRecorderHTTPMaxBodySize limits the maximum body size (in bytes) that
	// an HTTP recorder will capture.
	MDKeyRecorderHTTPMaxBodySize = "http.maxBodySize"

	// MDKeyLimiterRefreshInterval sets how often a limiter reloads its
	// configuration from an external source.
	MDKeyLimiterRefreshInterval = "limiter.refreshInterval"

	// MDKeyLimiterCleanupInterval sets how often a limiter purges expired
	// entries from its internal state.
	MDKeyLimiterCleanupInterval = "limiter.cleanupInterval"

	// MDKeyLimiterScope controls whether a cached traffic limiter's scope is
	// per-service ("service") or per-client ("client").
	MDKeyLimiterScope = "limiter.scope"

	// MDKeyObserverResetTraffic requests a traffic counter reset each time the
	// observer reports.
	MDKeyObserverResetTraffic = "observer.resetTraffic"

	// MDKeyObserverPeriod sets the interval between observer reports.
	MDKeyObserverPeriod = "observer.period"

	// MDKeyNetns is the network namespace name or path used for the listener
	// side (inbound).
	MDKeyNetns = "netns"

	// MDKeyNetnsOut is the network namespace name or path used for the handler
	// (outbound) side.
	MDKeyNetnsOut = "netns.out"

	// MDKeyDialTimeout sets the dial timeout for outbound connections.
	MDKeyDialTimeout = "dialTimeout"

	// MDKeyLabels holds static key/value labels attached to a service's
	// records and logs.
	MDKeyLabels = "labels"
)
