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

type CacheKey string

// NewCacheKey generates resolver cache key from question of dns query.
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

type Cache struct {
	m      sync.Map
	logger logger.Logger
}

func NewCache() *Cache {
	return &Cache{}
}

func (c *Cache) WithLogger(logger logger.Logger) *Cache {
	c.logger = logger
	return c
}

func (c *Cache) Load(ctx context.Context, key CacheKey) (msg *dns.Msg, ttl time.Duration) {
	v, ok := c.m.Load(key)
	if !ok {
		return
	}

	item, ok := v.(*cacheItem)
	if !ok {
		return
	}

	msg = item.msg.Copy()
	for i := range msg.Answer {
		d := uint32(time.Since(item.ts).Seconds())
		if msg.Answer[i].Header().Ttl > d {
			msg.Answer[i].Header().Ttl -= d
		} else {
			msg.Answer[i].Header().Ttl = 1
		}
	}
	ttl = item.ttl - time.Since(item.ts)

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
	} else {
		for i := range mr.Answer {
			mr.Answer[i].Header().Ttl = uint32(ttl.Seconds())
		}
	}

	c.m.Store(key, &cacheItem{
		msg: mr.Copy(),
		ts:  time.Now(),
		ttl: ttl,
	})

	if log := c.logger; log.IsLevelEnabled(logger.DebugLevel) {
		if sid := ctxvalue.SidFromContext(ctx); sid != "" {
			log = log.WithFields(map[string]any{
				"sid": sid,
			})
		}
		log.Debugf("resolver cache store: %s, ttl: %v", key, ttl)
	}
}

func (c *Cache) RefreshTTL(key CacheKey) {
	v, ok := c.m.Load(key)
	if !ok {
		return
	}

	item, ok := v.(*cacheItem)
	if !ok {
		return
	}
	item.ts = time.Now()
}
