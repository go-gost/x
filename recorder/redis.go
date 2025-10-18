package recorder

import (
	"context"

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
type RedisRecorderOption func(opts *redisRecorderOptions)

func RecorderRedisRecorderOption(recorder string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.recorder = recorder
	}
}

func DBRedisRecorderOption(db int) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.db = db
	}
}

func UsernameRedisRecorderOption(username string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.username = username
	}
}
func PasswordRedisRecorderOption(password string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.password = password
	}
}

func KeyRedisRecorderOption(key string) RedisRecorderOption {
	return func(opts *redisRecorderOptions) {
		opts.key = key
	}
}

type redisSetRecorder struct {
	recorder string
	client   *redis.Client
	key      string
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
	return r.client.Close()
}

type redisListRecorder struct {
	recorder string
	client   *redis.Client
	key      string
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
	return r.client.Close()
}

type redisSortedSetRecorder struct {
	recorder string
	client   *redis.Client
	key      string
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
	return r.client.Close()
}
