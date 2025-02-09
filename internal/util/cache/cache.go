package cache

import (
	"sync"
	"time"
)

type Item struct {
	v          interface{}
	expiration int64
}

func NewItem(v interface{}, d time.Duration) *Item {
	var expiration int64
	if d > 0 {
		expiration = time.Now().Add(d).UnixNano()
	}

	return &Item{
		v:          v,
		expiration: expiration,
	}
}

func (p *Item) Expired() bool {
	if p == nil {
		return true
	}
	return p.expiration > 0 && time.Now().UnixNano() > p.expiration
}

func (p *Item) Value() interface{} {
	if p == nil {
		return nil
	}
	return p.v
}

type Cache struct {
	items           map[string]*Item
	cleanupInterval time.Duration
	mu              sync.RWMutex
}

func NewCache(cleanupInterval time.Duration) *Cache {
	return &Cache{
		cleanupInterval: cleanupInterval,
		items:           make(map[string]*Item),
	}
}

func (c *Cache) Set(key string, item *Item) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = item
}

func (c *Cache) Get(key string) *Item {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.items[key]
}
