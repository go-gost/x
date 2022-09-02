package selector

import (
	"context"
	"time"

	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/selector"
)

type failFilter[T selector.Selectable] struct {
	maxFails    int
	failTimeout time.Duration
}

// FailFilter filters the dead objects.
// An object is marked as dead if its failed count is greater than MaxFails.
func FailFilter[T selector.Selectable](maxFails int, timeout time.Duration) selector.Filter[T] {
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
		maxFails := f.maxFails
		failTimeout := f.failTimeout
		if md := v.Metadata(); md != nil {
			if md.IsExists(labelMaxFails) {
				maxFails = mdutil.GetInt(md, labelMaxFails)
			}
			if md.IsExists(labelFailTimeout) {
				failTimeout = mdutil.GetDuration(md, labelFailTimeout)
			}
		}
		if maxFails <= 0 {
			maxFails = 1
		}
		if failTimeout <= 0 {
			failTimeout = DefaultFailTimeout
		}

		if marker := v.Marker(); marker != nil {
			if marker.Count() < int64(maxFails) ||
				time.Since(marker.Time()) >= failTimeout {
				l = append(l, v)
			}
		} else {
			l = append(l, v)
		}
	}
	return l
}

type backupFilter[T selector.Selectable] struct{}

// BackupFilter filters the backup objects.
// An object is marked as backup if its metadata has backup flag.
func BackupFilter[T selector.Selectable]() selector.Filter[T] {
	return &backupFilter[T]{}
}

// Filter filters backup objects.
func (f *backupFilter[T]) Filter(ctx context.Context, vs ...T) []T {
	if len(vs) <= 1 {
		return vs
	}

	var l, backups []T
	for _, v := range vs {
		if mdutil.GetBool(v.Metadata(), labelBackup) {
			backups = append(backups, v)
		} else {
			l = append(l, v)
		}
	}

	if len(l) == 0 {
		return backups
	}
	return l
}
