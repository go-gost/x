package resolver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/miekg/dns"
)

const (
	defaultTTL = 60 * time.Second
)

// CacheKey identifies a cached DNS response by question name, class, and type.
type CacheKey string

// NewCacheKey generates a resolver cache key from a DNS question.
// Returns an empty key if q is nil.
func NewCacheKey(q *dns.Question) CacheKey {
	if q == nil {
		return ""
	}
	key := fmt.Sprintf("%s%s.%s", q.Name, dns.Class(q.Qclass).String(), dns.Type(q.Qtype).String())
	return CacheKey(key)
}

type cacheItem struct {
	msg *dns.Msg
	ts  time.Time
	ttl time.Duration
}

// Cache stores DNS responses with TTL-based expiration and optional size bounding.
// A zero maxSize means unbounded (backward compatible).
//
// Load returns:
//   - (nil, 0) on cache miss
//   - (msg, ttl > 0) on fresh cache hit
//   - (msg, ttl <= 0) on expired cache hit (for stale-while-revalidate)
type Cache struct {
	mu      sync.RWMutex
	entries map[CacheKey]*cacheItem
	maxSize int // 0 = unlimited
	logger  logger.Logger
}

// NewCache creates an unbounded DNS cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[CacheKey]*cacheItem)}
}

// WithLogger sets the logger for cache debug messages.
func (c *Cache) WithLogger(logger logger.Logger) *Cache {
	c.logger = logger
	return c
}

// WithMaxSize sets the maximum number of entries. 0 means unlimited.
// When the limit is reached, expired entries are evicted first, then the oldest.
func (c *Cache) WithMaxSize(n int) *Cache {
	c.maxSize = n
	return c
}

// Load returns a cached DNS message and its remaining TTL.
// The returned message is a deep copy safe for caller mutation.
func (c *Cache) Load(ctx context.Context, key CacheKey) (msg *dns.Msg, ttl time.Duration) {
	var elapsed time.Duration
	c.mu.RLock()
	item, ok := c.entries[key]
	if ok {
		msg = item.msg.Copy()
		elapsed = time.Since(item.ts)
		ttl = item.ttl - elapsed
	}
	c.mu.RUnlock()
	if !ok {
		return
	}

	for i := range msg.Answer {
		d := uint32(elapsed.Seconds())
		if msg.Answer[i].Header().Ttl > d {
			msg.Answer[i].Header().Ttl -= d
		} else {
			msg.Answer[i].Header().Ttl = 1
		}
	}

	if log := c.logger; log.IsLevelEnabled(logger.DebugLevel) {
		if sid := ctxvalue.SidFromContext(ctx); sid != "" {
			log = log.WithFields(map[string]any{
				"sid": sid,
			})
		}
		log.Debugf("resolver cache hit: %s, ttl: %v", key, ttl)
	}

	return
}

// Store adds a DNS response to the cache. Negative ttl means "do not cache" and is
// silently skipped. Zero ttl uses the minimum TTL from the answer records (or
// defaultTTL if none have a positive TTL). Positive ttl overrides all answer TTLs.
func (c *Cache) Store(ctx context.Context, key CacheKey, mr *dns.Msg, ttl time.Duration) {
	if key == "" || mr == nil || ttl < 0 {
		return
	}

	if ttl == 0 {
		for _, answer := range mr.Answer {
			v := time.Duration(answer.Header().Ttl) * time.Second
			if ttl == 0 || ttl > v {
				ttl = v
			}
		}
		if ttl == 0 {
			ttl = defaultTTL
		}
	}

	cp := mr.Copy()
	if ttl > 0 {
		for i := range cp.Answer {
			cp.Answer[i].Header().Ttl = uint32(ttl.Seconds())
		}
	}

	c.mu.Lock()
	// Evict if over capacity.
	if c.maxSize > 0 {
		c.cleanupLocked()
		if len(c.entries) >= c.maxSize {
			// Evict the oldest entry.
			var oldestKey CacheKey
			var oldestTS time.Time
			for k, item := range c.entries {
				if oldestKey == "" || item.ts.Before(oldestTS) {
					oldestKey = k
					oldestTS = item.ts
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &cacheItem{
		msg: cp,
		ts:  time.Now(),
		ttl: ttl,
	}
	c.mu.Unlock()

	if log := c.logger; log.IsLevelEnabled(logger.DebugLevel) {
		if sid := ctxvalue.SidFromContext(ctx); sid != "" {
			log = log.WithFields(map[string]any{
				"sid": sid,
			})
		}
		log.Debugf("resolver cache store: %s, ttl: %v", key, ttl)
	}
}

// RefreshTTL resets the timestamp on a cached entry, extending its TTL.
func (c *Cache) RefreshTTL(key CacheKey) {
	c.mu.Lock()
	item, ok := c.entries[key]
	if ok {
		item.ts = time.Now()
	}
	c.mu.Unlock()
}

// cleanupLocked removes expired entries. Caller must hold c.mu.Lock.
func (c *Cache) cleanupLocked() {
	now := time.Now()
	for key, item := range c.entries {
		if now.Sub(item.ts) > item.ttl {
			delete(c.entries, key)
		}
	}
}
