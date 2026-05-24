package recorder

import (
	"context"
	"sync"

	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/recorder"
	xmetrics "github.com/go-gost/x/metrics"
	"github.com/go-redis/redis/v8"
)

type redisRecorderOptions struct {
	recorder string
	db       int
	username string
	password string
	key      string
}
// RedisRecorderOption configures Redis recorder options.
type RedisRecorderOption func(opts *redisRecorderOptions)

// RecorderRedisRecorderOption sets the recorder name for metrics labeling.
func RecorderRedisRecorderOption(recorder string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.recorder = recorder
	}
}

// DBRedisRecorderOption sets the Redis database number.
func DBRedisRecorderOption(db int) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.db = db
	}
}

// UsernameRedisRecorderOption sets the Redis username for authentication.
func UsernameRedisRecorderOption(username string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.username = username
	}
}
// PasswordRedisRecorderOption sets the Redis password for authentication.
func PasswordRedisRecorderOption(password string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.password = password
	}
}

// KeyRedisRecorderOption sets the Redis key for storing records.
func KeyRedisRecorderOption(key string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.key = key
	}
}

type redisSetRecorder struct {
	recorder  string
	client    *redis.Client
	key       string
	closeOnce sync.Once
}

// RedisSetRecorder records data to a redis set.
func RedisSetRecorder(addr string, opts ...RedisRecorderOption) recorder.Recorder {
	var options redisRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &redisSetRecorder{
		recorder: options.recorder,
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Username: options.username,
			Password: options.password,
			DB:       options.db,
		}),
		key: options.key,
	}
}

func (r *redisSetRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	xmetrics.GetCounter(xmetrics.MetricRecorderRecordsCounter, metrics.Labels{"recorder": r.recorder}).Inc()

	if r.key == "" {
		return nil
	}

	return r.client.SAdd(ctx, r.key, b).Err()
}

func (r *redisSetRecorder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.client.Close()
	})
	return err
}

type redisListRecorder struct {
	recorder  string
	client    *redis.Client
	key       string
	closeOnce sync.Once
}

// RedisListRecorder records data to a redis list.
func RedisListRecorder(addr string, opts ...RedisRecorderOption) recorder.Recorder {
	var options redisRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &redisListRecorder{
		recorder: options.recorder,
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Username: options.username,
			Password: options.password,
			DB:       options.db,
		}),
		key: options.key,
	}
}

func (r *redisListRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	xmetrics.GetCounter(xmetrics.MetricRecorderRecordsCounter, metrics.Labels{"recorder": r.recorder}).Inc()

	if r.key == "" {
		return nil
	}

	return r.client.LPush(ctx, r.key, b).Err()
}

func (r *redisListRecorder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.client.Close()
	})
	return err
}

type redisSortedSetRecorder struct {
	recorder  string
	client    *redis.Client
	key       string
	closeOnce sync.Once
}

// RedisSortedSetRecorder records data to a redis sorted set.
func RedisSortedSetRecorder(addr string, opts ...RedisRecorderOption) recorder.Recorder {
	var options redisRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &redisSortedSetRecorder{
		recorder: options.recorder,
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Username: options.username,
			Password: options.password,
			DB:       options.db,
		}),
		key: options.key,
	}
}

func (r *redisSortedSetRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	xmetrics.GetCounter(xmetrics.MetricRecorderRecordsCounter, metrics.Labels{"recorder": r.recorder}).Inc()

	if r.key == "" {
		return nil
	}

	return r.client.ZIncr(ctx, r.key, &redis.Z{
		Score:  1,
		Member: b,
	}).Err()
}

func (r *redisSortedSetRecorder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.client.Close()
	})
	return err
}
