// Package dashboard provides an in-process read model for the GOST
// monitoring dashboard. It consumes observer events, keeps bounded
// per-service and per-module series, and exposes a single JSON snapshot.
package dashboard

import "github.com/go-gost/core/observer"

// Additional observer event types used by the dashboard. EventType is a
// string type, so x can extend it without changing core.
const (
	EventModuleStats observer.EventType = "module_stats"
	EventModuleState observer.EventType = "module_state"
	EventModuleError observer.EventType = "module_error"
)

// Key is the stable identity of an observable node. Service is empty for
// modules shared by many services, such as hosts and resolvers.
type Key struct {
	Kind    string
	Name    string
	Service string
}

// ModuleStatsEvent carries cumulative module counters. It is never a delta:
// observer batches may be retried, so consumers must replace their stored
// values rather than add them.
type ModuleStatsEvent struct {
	Kind    string
	Name    string
	Service string

	Calls            uint64
	Hits             uint64
	Misses           uint64
	Errors           uint64
	InputBytes       uint64
	OutputBytes      uint64
	LatencySumMicros uint64
	LatencyCount     uint64
}

// Type returns EventModuleStats.
func (ModuleStatsEvent) Type() observer.EventType { return EventModuleStats }

// ModuleStateEvent reports a discrete module state change.
type ModuleStateEvent struct {
	Kind    string
	Name    string
	Service string
	State   string // enabled | disabled | degraded | failed
	Message string
}

// Type returns EventModuleState.
func (ModuleStateEvent) Type() observer.EventType { return EventModuleState }

// ModuleErrorEvent is a bounded diagnostic event. It also increments the
// module's error counter until the next cumulative stats snapshot.
//
// Seq is a per-module monotonically increasing sequence number. Producers
// must set it so retried observer batches are idempotent; a zero Seq keeps
// the legacy always-append behavior.
type ModuleErrorEvent struct {
	Kind    string
	Name    string
	Service string
	Message string
	Seq     uint64
}

// Type returns EventModuleError.
func (ModuleErrorEvent) Type() observer.EventType { return EventModuleError }
