package cache

import (
	"strings"

	"github.com/go-gost/core/cache"
	"github.com/go-gost/core/logger"
	xcache "github.com/go-gost/x/cache"
	"github.com/go-gost/x/config"
)

// ParseCache converts a CacheConfig into a cache.Cache. Memory and Redis
// backends are supported. Returns nil when cfg is nil or no backend is
// configured.
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

	if cfg.Redis != nil {
		return xcache.NewRedisCache(xcache.RedisOptions{
			Addr:       cfg.Redis.Addr,
			DB:         cfg.Redis.DB,
			Username:   cfg.Redis.Username,
			Password:   cfg.Redis.Password,
			DefaultTTL: cfg.Redis.TTL,
			KeyPrefix:  cfg.Redis.Key,
			Logger:     logger.Default(),
		})
	}

	return nil
}
