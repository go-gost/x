// Package cache provides in-memory implementations of the core cache.Cache
// interface.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/go-gost/core/cache"
	"github.com/go-gost/core/logger"
)

// EvictionPolicy selects which entry to remove when the cache is full.
type EvictionPolicy string

const (
	// EvictOldest removes the entry inserted least recently (by insertion time).
	EvictOldest EvictionPolicy = "oldest"
	// EvictLRU removes the entry accessed least recently.
	EvictLRU EvictionPolicy = "lru"
)

// Options configures a memory cache.
type Options struct {
	// DefaultTTL is applied to entries stored without an explicit TTL.
	// A non-positive value means entries never expire by default.
	DefaultTTL time.Duration
	// MaxSize bounds the number of entries. 0 means unbounded.
	MaxSize int
	// MaxBytes bounds the total size of stored data in bytes. 0 means unbounded.
	MaxBytes int64
	// CleanupInterval sets the period for the background expiry sweep.
	// A non-positive value disables the background goroutine.
	CleanupInterval time.Duration
	// Eviction is the policy used when MaxSize or MaxBytes is exceeded.
	// Defaults to EvictOldest.
	Eviction EvictionPolicy
	// Logger is used for debug logging. Optional.
	Logger logger.Logger
}

type entry struct {
	data       []byte
	expiration time.Time // zero = never expires
	created    time.Time
	lastAccess time.Time
}

// memoryCache is a concurrency-safe in-memory cache.Cache implementation.
type memoryCache struct {
	mu           sync.RWMutex
	entries      map[string]*entry
	currentBytes int64

	defaultTTL time.Duration
	maxSize    int
	maxBytes   int64
	eviction   EvictionPolicy
	logger     logger.Logger

	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// NewMemoryCache creates an in-memory cache. If opts.CleanupInterval is
// positive, a background goroutine periodically removes expired entries; it is
// stopped by Close.
func NewMemoryCache(opts Options) cache.Cache {
	eviction := opts.Eviction
	if eviction != EvictLRU {
		eviction = EvictOldest
	}

	c := &memoryCache{
		entries:     make(map[string]*entry),
		defaultTTL:  opts.DefaultTTL,
		maxSize:     opts.MaxSize,
		maxBytes:    opts.MaxBytes,
		eviction:    eviction,
		logger:      opts.Logger,
		stopCleanup: make(chan struct{}),
	}

	if opts.CleanupInterval > 0 {
		go c.cleanupLoop(opts.CleanupInterval)
	}

	return c
}

// Get returns the entry for key. An expired-but-present entry is returned with
// cache.ErrNotFound reserved for absent keys, so callers can serve stale.
func (c *memoryCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	c.mu.Lock()
	e, ok := c.entries[key]
	if ok {
		e.lastAccess = time.Now()
	}
	c.mu.Unlock()

	if !ok {
		return nil, cache.ErrNotFound
	}

	// Return a copy so callers can't mutate the stored buffer.
	data := make([]byte, len(e.data))
	copy(data, e.data)
	return &cache.Entry{Data: data, Expiration: e.expiration}, nil
}

// Set stores data under key. A non-positive TTL uses the cache default; a
// non-positive default means the entry never expires.
func (c *memoryCache) Set(ctx context.Context, key string, data []byte, opts ...cache.SetOption) error {
	var so cache.SetOptions
	for _, opt := range opts {
		opt(&so)
	}

	ttl := so.TTL
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	var expiration time.Time
	if ttl > 0 {
		expiration = time.Now().Add(ttl)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	now := time.Now()
	e := &entry{
		data:       cp,
		expiration: expiration,
		created:    now,
		lastAccess: now,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Replace: account for the size delta of an existing key.
	if old, ok := c.entries[key]; ok {
		c.currentBytes -= int64(len(old.data))
	}
	c.entries[key] = e
	c.currentBytes += int64(len(cp))

	c.evictLocked()

	return nil
}

// Delete removes key from the cache.
func (c *memoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		c.currentBytes -= int64(len(e.data))
		delete(c.entries, key)
	}
	c.mu.Unlock()
	return nil
}

// Close stops the background cleanup goroutine. Safe to call more than once.
// Implements io.Closer so the registry stops the goroutine on hot reload.
func (c *memoryCache) Close() error {
	c.stopOnce.Do(func() { close(c.stopCleanup) })
	return nil
}

func (c *memoryCache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCleanup:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, e := range c.entries {
				if !e.expiration.IsZero() && now.After(e.expiration) {
					c.currentBytes -= int64(len(e.data))
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// evictLocked enforces the size/byte bounds. It first drops expired entries,
// then evicts by policy until within bounds. Caller must hold c.mu.
func (c *memoryCache) evictLocked() {
	if !c.overCapacityLocked() {
		return
	}

	// First pass: drop expired entries — they're free wins.
	now := time.Now()
	for k, e := range c.entries {
		if !e.expiration.IsZero() && now.After(e.expiration) {
			c.currentBytes -= int64(len(e.data))
			delete(c.entries, k)
		}
	}

	// Second pass: evict by policy until within bounds.
	for c.overCapacityLocked() && len(c.entries) > 0 {
		var victim string
		var victimTS time.Time
		first := true
		for k, e := range c.entries {
			ts := e.created
			if c.eviction == EvictLRU {
				ts = e.lastAccess
			}
			if first || ts.Before(victimTS) {
				victim = k
				victimTS = ts
				first = false
			}
		}
		if e, ok := c.entries[victim]; ok {
			c.currentBytes -= int64(len(e.data))
			delete(c.entries, victim)
		}
	}
}

func (c *memoryCache) overCapacityLocked() bool {
	if c.maxSize > 0 && len(c.entries) > c.maxSize {
		return true
	}
	if c.maxBytes > 0 && c.currentBytes > c.maxBytes {
		return true
	}
	return false
}
