package quota

type RedisConfig struct {
	Addr     string
	Username string
	Password string
	DB       int
	Key      string
}

// redisStore is a no-op placeholder: a redis-configured quota behaves as
// in-memory only until the backend is implemented.
//
// TODO: implement using github.com/go-redis/redis/v8 (already a dependency).
// Suggested schema: HSET <Key> <name> <json(Record)> for Save, HGET for Load.
// See internal/loader/redis.go and recorder/redis.go for the patterns.
type redisStore struct {
	cfg RedisConfig
}

func NewRedisStore(cfg RedisConfig) Store {
	return &redisStore{cfg: cfg}
}

func (s *redisStore) Load(name string) (Record, bool, error) {
	return Record{}, false, nil
}

func (s *redisStore) Save(name string, rec Record) error {
	return nil
}
