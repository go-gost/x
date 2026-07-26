package cache

import (
	"strings"

	"github.com/go-gost/core/cache"
	"github.com/go-gost/core/logger"
	xcache "github.com/go-gost/x/cache"
	"github.com/go-gost/x/config"
)

// ParseCache converts a CacheConfig into a cache.Cache. Only the memory
// backend is currently supported. Returns nil when cfg is nil or no backend
// is configured.
func ParseCache(cfg *config.CacheConfig) cache.Cache {
	if cfg == nil {
		return nil
	}

	if cfg.Memory != nil {
		return xcache.NewMemoryCache(xcache.Options{
			DefaultTTL:      cfg.Memory.TTL,
			MaxSize:         cfg.Memory.MaxSize,
			MaxBytes:        cfg.Memory.MaxBytes,
			CleanupInterval: cfg.Memory.CleanupInterval,
			Eviction:        xcache.EvictionPolicy(strings.ToLower(cfg.Memory.Eviction)),
			Logger:          logger.Default(),
		})
	}

	return nil
}
