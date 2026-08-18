package selector

import (
	"context"
	"time"

	"github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/core/selector"
)

type failFilter[T any] struct {
	maxFails    int
	failTimeout time.Duration
}

// FailFilter filters the dead objects.
// An object is marked as dead if its failed count is greater than MaxFails.
func FailFilter[T any](maxFails int, timeout time.Duration) selector.Filter[T] {
	return &failFilter[T]{
		maxFails:    maxFails,
		failTimeout: timeout,
	}
}

// Filter filters dead objects.
func (f *failFilter[T]) Filter(ctx context.Context, vs ...T) []T {
	if len(vs) <= 1 {
		return vs
	}
	var l []T
	for _, v := range vs {
		if !IsFailed(v, f.maxFails, f.failTimeout) {
			l = append(l, v)
		}
	}
	return l
}

// IsFailed reports whether v is currently marked failed: its failure count
// has reached maxFails and the last failure is still within failTimeout.
// Per-item metadata keys "maxFails" and "failTimeout" override the given
// defaults. Items without a failure marker are never considered failed.
func IsFailed[T any](v T, maxFails int, failTimeout time.Duration) bool {
	maxFails, failTimeout = effectiveFailSettings(v, maxFails, failTimeout)

	mi, _ := any(v).(selector.Markable)
	if mi == nil || mi.Marker() == nil {
		return false
	}
	marker := mi.Marker()
	return !(marker.Count() < int64(maxFails) || time.Since(marker.Time()) >= failTimeout)
}

// effectiveFailSettings resolves the maxFails/failTimeout for v, honoring
// per-item metadata overrides and defaulting to 1 / DefaultFailTimeout.
func effectiveFailSettings[T any](v T, maxFails int, failTimeout time.Duration) (int, time.Duration) {
	if mi, _ := any(v).(metadata.Metadatable); mi != nil {
		if md := mi.Metadata(); md != nil {
			if md.IsExists(labelMaxFails) {
				maxFails = mdutil.GetInt(md, labelMaxFails)
			}
			if md.IsExists(labelFailTimeout) {
				failTimeout = mdutil.GetDuration(md, labelFailTimeout)
			}
		}
	}
	if maxFails <= 0 {
		maxFails = 1
	}
	if failTimeout <= 0 {
		failTimeout = DefaultFailTimeout
	}
	return maxFails, failTimeout
}

type backupFilter[T any] struct{}

// BackupFilter filters the backup objects.
// An object is marked as backup if its metadata has backup flag.
func BackupFilter[T any]() selector.Filter[T] {
	return &backupFilter[T]{}
}

// Filter filters backup objects.
func (f *backupFilter[T]) Filter(ctx context.Context, vs ...T) []T {
	if len(vs) <= 1 {
		return vs
	}

	var l, backups []T
	for _, v := range vs {
		if mi, _ := any(v).(metadata.Metadatable); mi != nil {
			if mdutil.GetBool(mi.Metadata(), labelBackup) {
				backups = append(backups, v)
				continue
			}
		}
		l = append(l, v)
	}

	if len(l) == 0 {
		return backups
	}
	return l
}
