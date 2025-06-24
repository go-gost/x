package auth

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	xauth "github.com/go-gost/x/auth"
	auth_plugin "github.com/go-gost/x/auth/plugin"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/plugin"
	"github.com/go-gost/x/registry"
)

func ParseAuther(cfg *config.AutherConfig) auth.Authenticator {
	if cfg == nil {
		return nil
	}

	if cfg.Plugin != nil {
		var tlsCfg *tls.Config
		if cfg.Plugin.TLS != nil {
			tlsCfg = &tls.Config{
				ServerName:         cfg.Plugin.TLS.ServerName,
				InsecureSkipVerify: !cfg.Plugin.TLS.Secure,
			}
		}
		switch cfg.Plugin.Type {
		case "http":
			return auth_plugin.NewHTTPPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TLSConfigOption(tlsCfg),
				plugin.TimeoutOption(cfg.Plugin.Timeout),
			)
		default:
			return auth_plugin.NewGRPCPlugin(
				cfg.Name, cfg.Plugin.Addr,
				plugin.TokenOption(cfg.Plugin.Token),
				plugin.TLSConfigOption(tlsCfg),
			)
		}
	}

	m := make(map[string]string)

	for _, user := range cfg.Auths {
		if user.Username == "" {
			continue
		}
		m[user.Username] = user.Password
	}

	opts := []xauth.Option{
		xauth.AuthsOption(m),
		xauth.ReloadPeriodOption(cfg.Reload),
		xauth.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xauth.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.Redis != nil && cfg.Redis.Addr != "" {
		opts = append(opts, xauth.RedisLoaderOption(loader.RedisHashLoader(
			cfg.Redis.Addr,
			loader.DBRedisLoaderOption(cfg.Redis.DB),
			loader.UsernameRedisLoaderOption(cfg.Redis.Username),
			loader.PasswordRedisLoaderOption(cfg.Redis.Password),
			loader.KeyRedisLoaderOption(cfg.Redis.Key),
		)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xauth.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xauth.NewAuthenticator(opts...)
}

func ParseAutherFromAuth(au *config.AuthConfig) auth.Authenticator {
	if au == nil || au.Username == "" {
		return nil
	}
	return xauth.NewAuthenticator(
		xauth.AuthsOption(
			map[string]string{
				au.Username: au.Password,
			},
		),
		xauth.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind": "auther",
		})),
	)
}

func Info(cfg *config.AuthConfig) *url.Userinfo {
	if cfg == nil {
		return nil
	}

	if cfg.File != "" {
		if f, _ := os.Open(cfg.File); f != nil {
			defer f.Close()
			if infos, _ := parseInfo(f, 1); len(infos) > 0 {
				return infos[0]
			}
		}
	}

	if cfg.Username == "" {
		return nil
	}

	if cfg.Password == "" {
		return url.User(cfg.Username)
	}
	return url.UserPassword(cfg.Username, cfg.Password)
}

func parseInfo(r io.Reader, max int) (infos []*url.Userinfo, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// line := strings.Replace(scanner.Text(), "\t", " ", -1)
		line := strings.TrimSpace(scanner.Text())
		if n := strings.IndexByte(line, '#'); n == 0 {
			continue
		}
		sp := strings.SplitN(line, " ", 2)
		if len(sp) == 1 {
			if k := strings.TrimSpace(sp[0]); k != "" {
				infos = append(infos, url.User(k))
			}
		}
		if len(sp) == 2 {
			if k := strings.TrimSpace(sp[0]); k != "" {
				infos = append(infos, url.UserPassword(k, strings.TrimSpace(sp[1])))
			}
		}

		if max > 0 && len(infos) >= max {
			break
		}
	}

	err = scanner.Err()
	return
}

func List(name string, names ...string) []auth.Authenticator {
	var authers []auth.Authenticator
	if auther := registry.AutherRegistry().Get(name); auther != nil {
		authers = append(authers, auther)
	}
	for _, s := range names {
		if auther := registry.AutherRegistry().Get(s); auther != nil {
			authers = append(authers, auther)
		}
	}
	return authers
}
