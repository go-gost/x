// Package quota implements a persisted, long-term traffic-volume limiter that
// can be shared across services by name. Unlike the rate limiters in
// limiter/traffic and limiter/rate, it accumulates total bytes within a window
// [startsAt, expiresAt) and stops the referencing service(s) once a byte limit
// is reached. Enforcement is fail-open outside the window.
package quota

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
)

var ErrQuotaExceeded = errors.New("quota: traffic limit reached")

const defaultFlushInterval = 10 * time.Second

type Direction int

const (
	DirectionTotal Direction = iota
	DirectionIn
	DirectionOut
)

func (d Direction) String() string {
	switch d {
	case DirectionIn:
		return "in"
	case DirectionOut:
		return "out"
	default:
		return "total"
	}
}

// Options seeds a Limiter. Limit and the window are config-authoritative; a
// persisted counter is restored only for a matching window (see NewLimiter).
type Options struct {
	Limit     uint64
	StartsAt  time.Time
	ExpiresAt time.Time
	Direction Direction
	Flush     time.Duration
	Store     Store
	Logger    logger.Logger
}

// Update overwrites runtime state; a nil field is left unchanged.
type Update struct {
	Used      *uint64
	Limit     *uint64
	StartsAt  *time.Time
	ExpiresAt *time.Time
}

type Snapshot struct {
	Used          uint64
	Limit         uint64
	StartsAtUnix  int64
	ExpiresAtUnix int64
	Active        bool
	Expired       bool
	Blocked       bool
	Direction     string
}

type Limiter struct {
	name      string
	direction Direction
	flush     time.Duration
	store     Store
	log       logger.Logger

	used      atomic.Uint64
	limit     atomic.Uint64
	startsAt  atomic.Int64 // unixnano; 0 = unset
	expiresAt atomic.Int64 // unixnano; 0 = unset
	blocked   atomic.Bool
	dirty     atomic.Bool
	closed    atomic.Bool

	mu     sync.Mutex
	waitCh chan struct{} // closed+replaced to broadcast a state change

	closeOnce sync.Once
	done      chan struct{}
}

func NewLimiter(name string, opts Options) *Limiter {
	l := &Limiter{
		name:      name,
		direction: opts.Direction,
		flush:     opts.Flush,
		store:     opts.Store,
		log:       opts.Logger,
		waitCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	if l.flush <= 0 {
		l.flush = defaultFlushInterval
	}
	if l.log == nil {
		l.log = xlogger.Nop()
	}

	l.limit.Store(opts.Limit)
	sa := unixNanoOrZero(opts.StartsAt)
	ea := unixNanoOrZero(opts.ExpiresAt)
	l.startsAt.Store(sa)
	l.expiresAt.Store(ea)

	// Restore the counter only within the same window: a changed window (a new
	// period pushed via config) starts fresh.
	if l.store != nil {
		if rec, ok, err := l.store.Load(name); err != nil {
			l.log.Warnf("quota: load %s: %v", name, err)
		} else if ok && rec.StartsAt == sa && rec.ExpiresAt == ea {
			l.used.Store(rec.Used)
		}
	}

	l.blocked.Store(l.enforcing(time.Now()) && l.used.Load() >= l.limit.Load())
	go l.run()
	return l
}

func (l *Limiter) active(now time.Time) bool {
	n := now.UnixNano()
	if sa := l.startsAt.Load(); sa != 0 && n < sa {
		return false
	}
	if ea := l.expiresAt.Load(); ea != 0 && n >= ea {
		return false
	}
	return true
}

func (l *Limiter) enforcing(now time.Time) bool {
	return l.limit.Load() > 0 && l.active(now)
}

func (l *Limiter) Blocked() bool {
	if l.closed.Load() || !l.blocked.Load() {
		return false
	}
	return l.enforcing(time.Now())
}

func (l *Limiter) AddIn(n int)  { l.add(int64(n), DirectionIn) }
func (l *Limiter) AddOut(n int) { l.add(int64(n), DirectionOut) }

func (l *Limiter) add(n int64, dir Direction) {
	if n <= 0 || l.closed.Load() {
		return
	}
	switch l.direction {
	case DirectionIn:
		if dir != DirectionIn {
			return
		}
	case DirectionOut:
		if dir != DirectionOut {
			return
		}
	}
	if !l.active(time.Now()) {
		return
	}
	used := l.used.Add(uint64(n))
	l.dirty.Store(true)
	if lim := l.limit.Load(); lim > 0 && used >= lim {
		l.block()
	}
}

// block is hot-path: no lock, no I/O, no wakeup (parking only happens on the
// next Accept).
func (l *Limiter) block() {
	if l.blocked.CompareAndSwap(false, true) {
		l.log.Warnf("quota: %s reached limit %d bytes, stopping", l.name, l.limit.Load())
	}
}

// WaitChan must be fetched before checking Blocked to avoid a missed wakeup.
func (l *Limiter) WaitChan() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waitCh
}

func (l *Limiter) notify() {
	l.mu.Lock()
	close(l.waitCh)
	l.waitCh = make(chan struct{})
	l.mu.Unlock()
}

func (l *Limiter) Update(u Update) {
	if u.Used != nil {
		l.used.Store(*u.Used)
	}
	if u.Limit != nil {
		l.limit.Store(*u.Limit)
	}
	if u.StartsAt != nil {
		l.startsAt.Store(unixNanoOrZero(*u.StartsAt))
	}
	if u.ExpiresAt != nil {
		l.expiresAt.Store(unixNanoOrZero(*u.ExpiresAt))
	}
	l.reevaluate()
}

func (l *Limiter) reevaluate() {
	now := time.Now()
	shouldBlock := l.enforcing(now) && l.used.Load() >= l.limit.Load()
	l.blocked.Store(shouldBlock)
	if !shouldBlock {
		l.notify()
	}
	l.flushNow()
}

func (l *Limiter) Snapshot() Snapshot {
	now := time.Now()
	ea := l.expiresAt.Load()
	return Snapshot{
		Used:          l.used.Load(),
		Limit:         l.limit.Load(),
		StartsAtUnix:  nanoToSec(l.startsAt.Load()),
		ExpiresAtUnix: nanoToSec(ea),
		Active:        l.active(now),
		Expired:       ea != 0 && now.UnixNano() >= ea,
		Blocked:       l.Blocked(),
		Direction:     l.direction.String(),
	}
}

func (l *Limiter) run() {
	flushT := time.NewTicker(l.flush)
	defer flushT.Stop()
	boundT := time.NewTicker(time.Second)
	defer boundT.Stop()

	wasActive := l.active(time.Now())

	for {
		select {
		case <-l.done:
			return

		case <-flushT.C:
			if l.dirty.Swap(false) {
				l.persist()
			}

		case <-boundT.C:
			now := time.Now()
			act := l.active(now)
			if act == wasActive {
				continue
			}
			wasActive = act
			if act {
				l.blocked.Store(l.limit.Load() > 0 && l.used.Load() >= l.limit.Load())
			} else {
				l.blocked.Store(false)
			}
			l.notify()
			l.persist()
		}
	}
}

func (l *Limiter) flushNow() {
	l.dirty.Store(false)
	l.persist()
}

func (l *Limiter) persist() {
	if l.store == nil {
		return
	}
	rec := Record{
		Used:      l.used.Load(),
		Limit:     l.limit.Load(),
		StartsAt:  l.startsAt.Load(),
		ExpiresAt: l.expiresAt.Load(),
		UpdatedAt: time.Now().UnixNano(),
	}
	if err := l.store.Save(l.name, rec); err != nil {
		l.log.Warnf("quota: save %s: %v", l.name, err)
	}
}

// Close makes the limiter inert (Blocked false, counting a no-op) so deleting a
// shared quota releases the referencing services instead of tearing them down.
// Called by the registry on Unregister.
func (l *Limiter) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.done)
		l.flushNow()
		l.notify()
	})
	return nil
}

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func nanoToSec(n int64) int64 {
	if n == 0 {
		return 0
	}
	return n / int64(time.Second)
}
