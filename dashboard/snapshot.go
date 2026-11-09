package dashboard

import "time"

// Snapshot is the dashboard read model returned by GET /dashboard/snapshot.
type Snapshot struct {
	Version               int                        `json:"version"`
	GeneratedAt           time.Time                  `json:"generatedAt"`
	StartedAt             time.Time                  `json:"startedAt"`
	SampleIntervalSeconds int                        `json:"sampleIntervalSeconds"`
	MetricsEnabled        bool                       `json:"metricsEnabled"`
	Services              map[string]ServiceSnapshot `json:"services"`
	Modules               []ModuleSnapshot           `json:"modules"`
	Chains                map[string]ChainSnapshot   `json:"chains"`
	Events                []EventRecord              `json:"events"`
	History               []HistoryPoint             `json:"history"`
}

// ServiceSnapshot is the runtime state and traffic of one service.
type ServiceSnapshot struct {
	Name  string       `json:"name"`
	State string       `json:"state"`
	Stats ServiceStats `json:"stats"`
	Rate  ServiceRate  `json:"rate"`
}

// ServiceStats contains cumulative service counters.
type ServiceStats struct {
	TotalConns   uint64 `json:"totalConns"`
	CurrentConns uint64 `json:"currentConns"`
	InputBytes   uint64 `json:"inputBytes"`
	OutputBytes  uint64 `json:"outputBytes"`
	TotalErrs    uint64 `json:"totalErrs"`
}

// ServiceRate contains per-second byte rates derived from history samples.
type ServiceRate struct {
	InputBytesPerSecond  float64 `json:"inputBytesPerSecond"`
	OutputBytesPerSecond float64 `json:"outputBytesPerSecond"`
}

// ModuleSnapshot is the runtime state and counters of one module instance.
type ModuleSnapshot struct {
	Kind    string      `json:"kind"`
	Name    string      `json:"name"`
	Service string      `json:"service,omitempty"`
	State   string      `json:"state,omitempty"`
	Stats   ModuleStats `json:"stats"`
}

// ModuleStats contains cumulative module counters and latency totals.
type ModuleStats struct {
	Calls            uint64 `json:"calls"`
	Hits             uint64 `json:"hits"`
	Misses           uint64 `json:"misses"`
	Errors           uint64 `json:"errors"`
	InputBytes       uint64 `json:"inputBytes"`
	OutputBytes      uint64 `json:"outputBytes"`
	LatencySumMicros uint64 `json:"latencySumMicros"`
	LatencyCount     uint64 `json:"latencyCount"`
	CacheHits        uint64 `json:"cacheHits"`
	CacheMisses      uint64 `json:"cacheMisses"`
	CacheStores      uint64 `json:"cacheStores"`
}

// ChainSnapshot is the runtime state of one proxy chain.
type ChainSnapshot struct {
	Name  string         `json:"name"`
	Hops  []HopSnapshot  `json:"hops,omitempty"`
	Nodes []NodeSnapshot `json:"nodes,omitempty"`
	Stats ChainStats     `json:"stats"`
}

// HopSnapshot is one hop inside a chain.
type HopSnapshot struct {
	Name  string         `json:"name"`
	Nodes []NodeSnapshot `json:"nodes"`
}

// NodeSnapshot is one node inside a hop.
type NodeSnapshot struct {
	Name  string     `json:"name"`
	State string     `json:"state,omitempty"`
	Stats ChainStats `json:"stats"`
}

// ChainStats contains cumulative chain connection counters.
type ChainStats struct {
	Connects                 uint64 `json:"connects"`
	Errors                   uint64 `json:"errors"`
	ConnectDurationSumMicros uint64 `json:"connectDurationSumMicros"`
	ConnectCount             uint64 `json:"connectCount"`
}

// EventRecord is one bounded diagnostic event.
type EventRecord struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Kind    string    `json:"kind"`
	Name    string    `json:"name"`
	Service string    `json:"service,omitempty"`
	Message string    `json:"message"`
}

// HistoryPoint is one periodic sample of service counters.
type HistoryPoint struct {
	Time     time.Time                 `json:"time"`
	Services map[string]ServiceHistory `json:"services"`
}

// ServiceHistory is the subset of service counters kept in history.
type ServiceHistory struct {
	CurrentConns uint64 `json:"currentConns"`
	InputBytes   uint64 `json:"inputBytes"`
	OutputBytes  uint64 `json:"outputBytes"`
}
