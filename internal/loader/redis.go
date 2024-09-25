package loader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/go-redis/redis/v8"
)

const (
	DefaultRedisKey = "gost"
)

type redisLoaderOptions struct {
	db       int
	username string
	password string
	key      string
}

type RedisLoaderOption func(opts *redisLoaderOptions)

func DBRedisLoaderOption(db int) RedisLoaderOption {
	return func(opts *redisLoaderOptions) {
		opts.db = db
	}
}

func UsernameRedisLoaderOption(username string) RedisLoaderOption {
	return func(opts *redisLoaderOptions) {
		opts.username = username
	}
}

func PasswordRedisLoaderOption(password string) RedisLoaderOption {
	return func(opts *redisLoaderOptions) {
		opts.password = password
	}
}

func KeyRedisLoaderOption(key string) RedisLoaderOption {
	return func(opts *redisLoaderOptions) {
		opts.key = key
	}
}

type redisStringLoader struct {
	client *redis.Client
	key    string
}

// RedisStringLoader loads data from redis string.
func RedisStringLoader(addr string, opts ...RedisLoaderOption) Loader {
	var options redisLoaderOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	key := options.key
	if key == "" {
		key = DefaultRedisKey
	}

	return &redisStringLoader{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: options.password,
			DB:       options.db,
		}),
		key: key,
	}
}

func (p *redisStringLoader) Load(ctx context.Context) (io.Reader, error) {
	v, err := p.client.Get(ctx, p.key).Bytes()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(v), nil
}

func (p *redisStringLoader) Close() error {
	return p.client.Close()
}

type redisSetLoader struct {
	client *redis.Client
	key    string
}

// RedisSetLoader loads data from redis set.
func RedisSetLoader(addr string, opts ...RedisLoaderOption) Loader {
	var options redisLoaderOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	key := options.key
	if key == "" {
		key = DefaultRedisKey
	}

	return &redisSetLoader{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: options.password,
			DB:       options.db,
		}),
		key: key,
	}
}

func (p *redisSetLoader) Load(ctx context.Context) (io.Reader, error) {
	v, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader([]byte(strings.Join(v, "\n"))), nil
}

// List implements Lister interface{}
func (p *redisSetLoader) List(ctx context.Context) ([]string, error) {
	return p.client.SMembers(ctx, p.key).Result()
}

func (p *redisSetLoader) Close() error {
	return p.client.Close()
}

type redisListLoader struct {
	client *redis.Client
	key    string
}

// RedisListLoader loads data from redis list.
func RedisListLoader(addr string, opts ...RedisLoaderOption) Loader {
	var options redisLoaderOptions
	for _, opt := range opts {
		opt(&options)
	}

	key := options.key
	if key == "" {
		key = DefaultRedisKey
	}

	return &redisListLoader{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: options.password,
			DB:       options.db,
		}),
		key: key,
	}
}

func (p *redisListLoader) Load(ctx context.Context) (io.Reader, error) {
	v, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader([]byte(strings.Join(v, "\n"))), nil
}

// List implements Lister interface{}
func (p *redisListLoader) List(ctx context.Context) ([]string, error) {
	return p.client.LRange(ctx, p.key, 0, -1).Result()
}

func (p *redisListLoader) Close() error {
	return p.client.Close()
}

type redisHashLoader struct {
	client *redis.Client
	key    string
}

// RedisHashLoader loads data from redis hash.
func RedisHashLoader(addr string, opts ...RedisLoaderOption) Loader {
	var options redisLoaderOptions
	for _, opt := range opts {
		opt(&options)
	}

	key := options.key
	if key == "" {
		key = DefaultRedisKey
	}

	return &redisHashLoader{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: options.password,
			DB:       options.db,
		}),
		key: key,
	}
}

func (p *redisHashLoader) Load(ctx context.Context) (io.Reader, error) {
	m, err := p.Map(ctx)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	for k, v := range m {
		fmt.Fprintf(&b, "%s %s\n", k, v)
	}
	return bytes.NewBufferString(b.String()), nil
}

// List implements Lister interface{}
func (p *redisHashLoader) List(ctx context.Context) (list []string, err error) {
	m, err := p.Map(ctx)
	if err != nil {
		return
	}

	for k, v := range m {
		list = append(list, fmt.Sprintf("%s %s", k, v))
	}

	return
}

// Map implements Mapper interface{}
func (p *redisHashLoader) Map(ctx context.Context) (map[string]string, error) {
	return p.client.HGetAll(ctx, p.key).Result()
}

func (p *redisHashLoader) Close() error {
	return p.client.Close()
}
