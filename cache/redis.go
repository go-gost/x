package cache

import (
	"context"
	"time"

	"github.com/go-gost/core/cache"
	"github.com/go-gost/core/logger"
	"github.com/go-redis/redis/v8"
)

// defaultKeyPrefix is prepended to cache keys when RedisOptions.KeyPrefix is empty.
const defaultKeyPrefix = "gost:cache:"

// RedisOptions configures a Redis cache.
type RedisOptions struct {
	// Addr is the Redis server address (host:port).
	Addr string
	// DB is the Redis database number.
	DB int
	// Username for Redis authentication. Optional.
	Username string
	// Password for Redis authentication. Optional.
	Password string
	// DefaultTTL is applied to entries stored without an explicit TTL.
	// A non-positive value means entries never expire by default.
	DefaultTTL time.Duration
	// KeyPrefix is prepended to all cache keys. Defaults to "gost:cache:".
	KeyPrefix string
	// Logger is used for debug logging. Optional.
	Logger logger.Logger
}

// redisCache is a cache.Cache backed by a Redis server.
//
// Redis expires keys natively, so an expired entry is a true miss here — the
// interface's serve-stale contract (returning expired entries from Get) does
// not apply to this backend.
type redisCache struct {
	client     *redis.Client
	defaultTTL time.Duration
	keyPrefix  string
	logger     logger.Logger
}

// NewRedisCache creates a Redis-backed cache. Close releases the underlying
// client connections.
func NewRedisCache(opts RedisOptions) cache.Cache {
	keyPrefix := opts.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}

	return &redisCache{
		client: redis.NewClient(&redis.Options{
			Addr:     opts.Addr,
			Username: opts.Username,
			Password: opts.Password,
			DB:       opts.DB,
		}),
		defaultTTL: opts.DefaultTTL,
		keyPrefix:  keyPrefix,
		logger:     opts.Logger,
	}
}

// Get returns the entry for key, or cache.ErrNotFound if the key is absent
// (including keys Redis has already expired).
func (c *redisCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	k := c.keyPrefix + key

	pipe := c.client.Pipeline()
	getCmd := pipe.Get(ctx, k)
	ttlCmd := pipe.PTTL(ctx, k)
	if _, err := pipe.Exec(ctx); err != nil {
		if err == redis.Nil {
			return nil, cache.ErrNotFound
		}
		return nil, err
	}

	entry := &cache.Entry{
		Data: []byte(getCmd.Val()),
	}
	if ttl := ttlCmd.Val(); ttl > 0 {
		entry.Expiration = time.Now().Add(ttl)
	}
	return entry, nil
}

// Set stores data under key. A non-positive TTL (after applying the default)
// stores the entry without expiration.
func (c *redisCache) Set(ctx context.Context, key string, data []byte, opts ...cache.SetOption) error {
	var options cache.SetOptions
	for _, opt := range opts {
		opt(&options)
	}

	ttl := options.TTL
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	if ttl < 0 {
		ttl = 0 // redis: 0 = no expiration
	}

	return c.client.Set(ctx, c.keyPrefix+key, data, ttl).Err()
}

// Delete removes key from the cache. Deleting an absent key is a no-op.
func (c *redisCache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.keyPrefix+key).Err()
}

// Close releases the Redis client. Implements io.Closer so the registry
// closes the client on hot reload.
func (c *redisCache) Close() error {
	return c.client.Close()
}
