package quota

import (
	"strings"
	"time"

	"github.com/alecthomas/units"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xquota "github.com/go-gost/x/limiter/quota"
)

// ParseQuotaLimiter is best-effort: malformed fields are logged and treated as unset.
func ParseQuotaLimiter(cfg *config.QuotaConfig) *xquota.Limiter {
	if cfg == nil {
		return nil
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":  "quota",
		"quota": cfg.Name,
	})

	var limit uint64
	if s := strings.TrimSpace(cfg.Limit); s != "" && s != "0" {
		if v, err := units.ParseBase2Bytes(s); err != nil {
			log.Warnf("quota: parse limit %q: %v", s, err)
		} else if v > 0 {
			limit = uint64(v)
		}
	}

	var dir xquota.Direction
	switch strings.ToLower(strings.TrimSpace(cfg.Direction)) {
	case "in":
		dir = xquota.DirectionIn
	case "out":
		dir = xquota.DirectionOut
	default:
		dir = xquota.DirectionTotal
	}

	var flush time.Duration
	if s := strings.TrimSpace(cfg.Flush); s != "" {
		if d, err := time.ParseDuration(s); err != nil {
			log.Warnf("quota: parse flush %q: %v", s, err)
		} else {
			flush = d
		}
	}

	return xquota.NewLimiter(cfg.Name, xquota.Options{
		Limit:     limit,
		StartsAt:  parseQuotaTime(cfg.StartsAt, log, "startsAt"),
		ExpiresAt: parseQuotaTime(cfg.ExpiresAt, log, "expiresAt"),
		Direction: dir,
		Flush:     flush,
		Store:     parseQuotaStore(cfg.Store, log),
		Logger:    log,
	})
}

func parseQuotaTime(s string, log logger.Logger, field string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Warnf("quota: parse %s %q: %v", field, s, err)
		return time.Time{}
	}
	return t
}

func parseQuotaStore(sc *config.QuotaStoreConfig, log logger.Logger) xquota.Store {
	const defaultFile = "gost-quota.json"

	if sc == nil || sc.Type == "" || strings.EqualFold(sc.Type, "file") {
		path := defaultFile
		if sc != nil && strings.TrimSpace(sc.File) != "" {
			path = sc.File
		}
		return xquota.NewFileStore(path)
	}

	if strings.EqualFold(sc.Type, "redis") {
		log.Warnf("quota: redis store not implemented; counter will not be persisted")
		var rc config.QuotaRedisConfig
		if sc.Redis != nil {
			rc = *sc.Redis
		}
		return xquota.NewRedisStore(xquota.RedisConfig{
			Addr:     rc.Addr,
			Username: rc.Username,
			Password: rc.Password,
			DB:       rc.DB,
			Key:      rc.Key,
		})
	}

	log.Warnf("quota: unknown store type %q; using file store %q", sc.Type, defaultFile)
	return xquota.NewFileStore(defaultFile)
}
