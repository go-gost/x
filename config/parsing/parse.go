package parsing

const (
	MDKeyProxyProtocol = "proxyProtocol"
	MDKeyInterface     = "interface"
	MDKeySoMark        = "so_mark"
	MDKeyHash          = "hash"
	MDKeyPreUp         = "preUp"
	MDKeyPreDown       = "preDown"
	MDKeyPostUp        = "postUp"
	MDKeyPostDown      = "postDown"
	MDKeyIgnoreChain   = "ignoreChain"
	MDKeyEnableStats   = "enableStats"

	MDKeyRecorderDirection       = "direction"
	MDKeyRecorderTimestampFormat = "timeStampFormat"
	MDKeyRecorderHexdump         = "hexdump"
	MDKeyRecorderHTTPBody        = "http.body"
	MDKeyRecorderHTTPMaxBodySize = "http.maxBodySize"

	MDKeyLimiterRefreshInterval = "limiter.refreshInterval"
	MDKeyLimiterCleanupInterval = "limiter.cleanupInterval"
	MDKeyLimiterScope           = "limiter.scope"

	MDKeyObserverResetTraffic = "observer.resetTraffic"
	MDKeyObserverPeriod       = "observer.period"

	MDKeyNetns    = "netns"
	MDKeyNetnsOut = "netns.out"

	MDKeyDialTimeout = "dialTimeout"
)
