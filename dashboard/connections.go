package dashboard

import (
	"time"

	"github.com/go-gost/x/recorder"
)

// PathHop mirrors recorder.PathHop as a public read model for the UI.
type PathHop = recorder.PathHop

// ConnectionRecord is the public read model for the history endpoint.
type ConnectionRecord struct {
	SID        string            `json:"sid"`
	Service    string            `json:"service"`
	ClientIP   string            `json:"clientIP,omitempty"`
	RemoteAddr string            `json:"remoteAddr"`
	BytesIn    uint64            `json:"bytesIn"`
	BytesOut   uint64            `json:"bytesOut"`
	DurationMs uint64            `json:"durationMs"`
	Chain      string            `json:"chain,omitempty"`
	Path       []PathHop         `json:"path"`
	Err        string            `json:"err,omitempty"`
	Time       string            `json:"time"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// connectionsLocked builds the newest-first slice, applying the service/sid
// filters. It runs with the collector lock held.
func (c *Collector) connectionsLocked(limit int, service, sid string) []ConnectionRecord {
	cap := c.connectionsLimit
	if len(c.connections) < cap {
		cap = len(c.connections)
	}
	if limit > 0 && limit < cap {
		cap = limit
	}
	out := make([]ConnectionRecord, 0, cap)
	for i := len(c.connections) - 1; i >= 0 && len(out) < cap; i-- {
		rec := c.connections[i]
		if service != "" && rec.Service != service {
			continue
		}
		if sid != "" && rec.SID != sid {
			continue
		}
		out = append(out, cloneConnection(rec))
	}
	return out
}

// Connections returns the recorded connections, newest first. A limit <= 0
// returns everything the ring holds.
func (c *Collector) Connections(limit int, service, sid string) []ConnectionRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectionsLocked(limit, service, sid)
}

// RecordConnection stores one connection snapshot. The record is copied, so
// the caller may reuse or mutate its own struct after the call returns.
func (c *Collector) RecordConnection(rec ConnectionRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connectionsLimit <= 0 {
		return
	}
	c.connections = append(c.connections, cloneConnection(rec))
	for len(c.connections) > c.connectionsLimit {
		c.connections = c.connections[1:]
	}
}

func cloneConnection(rec ConnectionRecord) ConnectionRecord {
	out := rec
	if len(rec.Path) > 0 {
		out.Path = append([]PathHop(nil), rec.Path...)
	}
	if len(rec.Labels) > 0 {
		labels := make(map[string]string, len(rec.Labels))
		for k, v := range rec.Labels {
			labels[k] = v
		}
		out.Labels = labels
	}
	return out
}

// connectionRecordFromRecorder converts a recorder object into a connection
// record, copying the path and labels so later mutation can't corrupt the ring.
func connectionRecordFromRecorder(final *recorder.HandlerRecorderObject) ConnectionRecord {
	ms := final.Duration.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	rec := ConnectionRecord{
		SID:        final.SID,
		Service:    final.Service,
		ClientIP:   final.ClientIP,
		RemoteAddr: final.RemoteAddr,
		BytesIn:    final.InputBytes,
		BytesOut:   final.OutputBytes,
		DurationMs: uint64(ms),
		Chain:      final.Chain,
		Err:        final.Err,
		Time:       final.Time.UTC().Format(time.RFC3339),
		Labels:     final.Labels,
	}
	if len(final.Path) > 0 {
		rec.Path = append([]PathHop(nil), final.Path...)
	}
	return rec
}

// recordConnection adapts a recorder object into the ring. It is a no-op
// unless dashboard is enabled, so the wiring in Enable is the only gate.
func recordConnection(final *recorder.HandlerRecorderObject) {
	Default().RecordConnection(connectionRecordFromRecorder(final))
}
