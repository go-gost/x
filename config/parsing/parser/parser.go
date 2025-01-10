package parser

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/cmd"
	xmd "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

var (
	defaultParser = &parser{}
)

func Init(args Args) {
	defaultParser = &parser{
		args: args,
	}
}

func Parse() (*config.Config, error) {
	return defaultParser.Parse()
}

type Args struct {
	CfgFile     string
	Services    []string
	Nodes       []string
	Debug       bool
	Trace       bool
	ApiAddr     string
	MetricsAddr string
}

type parser struct {
	args Args
}

func (p *parser) Parse() (*config.Config, error) {
	cfg := &config.Config{}

	cfgFile := p.args.CfgFile
	if cfgFile != "" {
		cfgFile = strings.TrimSpace(cfgFile)
		if strings.HasPrefix(cfgFile, "{") && strings.HasSuffix(cfgFile, "}") {
			if err := json.Unmarshal([]byte(cfgFile), cfg); err != nil {
				return nil, err
			}
		} else {
			if err := cfg.ReadFile(cfgFile); err != nil {
				return nil, err
			}
		}
	}

	cmdCfg, err := cmd.BuildConfigFromCmd(p.args.Services, p.args.Nodes)
	if err != nil {
		return nil, err
	}
	cfg = mergeConfig(cfg, cmdCfg)

	if len(cfg.Services) == 0 && p.args.ApiAddr == "" && cfg.API == nil {
		if err := cfg.Load(); err != nil {
			return nil, err
		}
	}

	if v := os.Getenv("GOST_LOGGER_LEVEL"); v != "" {
		cfg.Log = &config.LogConfig{
			Level: v,
		}
	}
	if v := os.Getenv("GOST_API"); v != "" {
		cfg.API = &config.APIConfig{
			Addr: v,
		}
	}
	if v := os.Getenv("GOST_METRICS"); v != "" {
		cfg.Metrics = &config.MetricsConfig{
			Addr: v,
		}
	}
	if v := os.Getenv("GOST_PROFILING"); v != "" {
		cfg.Profiling = &config.ProfilingConfig{
			Addr: v,
		}
	}

	if p.args.Debug || p.args.Trace {
		if cfg.Log == nil {
			cfg.Log = &config.LogConfig{}
		}

		cfg.Log.Level = string(logger.DebugLevel)
		if p.args.Trace {
			cfg.Log.Level = string(logger.TraceLevel)
		}
	}

	if p.args.ApiAddr != "" {
		cfg.API = &config.APIConfig{
			Addr: p.args.ApiAddr,
		}
		if url, _ := cmd.Norm(p.args.ApiAddr); url != nil {
			cfg.API.Addr = url.Host
			if url.User != nil {
				username := url.User.Username()
				password, _ := url.User.Password()
				cfg.API.Auth = &config.AuthConfig{
					Username: username,
					Password: password,
				}
			}
			m := map[string]any{}
			for k, v := range url.Query() {
				if len(v) > 0 {
					m[k] = v[0]
				}
			}
			md := xmd.NewMetadata(m)
			cfg.API.PathPrefix = mdutil.GetString(md, "pathPrefix")
			cfg.API.AccessLog = mdutil.GetBool(md, "accesslog")
		}
	}
	if p.args.MetricsAddr != "" {
		cfg.Metrics = &config.MetricsConfig{
			Addr: p.args.MetricsAddr,
		}
		if url, _ := cmd.Norm(p.args.MetricsAddr); url != nil {
			cfg.Metrics.Addr = url.Host
			if url.User != nil {
				username := url.User.Username()
				password, _ := url.User.Password()
				cfg.Metrics.Auth = &config.AuthConfig{
					Username: username,
					Password: password,
				}
			}
			m := map[string]any{}
			for k, v := range url.Query() {
				if len(v) > 0 {
					m[k] = v[0]
				}
			}
			md := xmd.NewMetadata(m)
			cfg.Metrics.Path = mdutil.GetString(md, "path")
		}
	}

	return cfg, nil
}

func mergeConfig(cfg1, cfg2 *config.Config) *config.Config {
	if cfg1 == nil {
		return cfg2
	}
	if cfg2 == nil {
		return cfg1
	}

	cfg := &config.Config{
		Services:   append(cfg1.Services, cfg2.Services...),
		Chains:     append(cfg1.Chains, cfg2.Chains...),
		Hops:       append(cfg1.Hops, cfg2.Hops...),
		Authers:    append(cfg1.Authers, cfg2.Authers...),
		Admissions: append(cfg1.Admissions, cfg2.Admissions...),
		Bypasses:   append(cfg1.Bypasses, cfg2.Bypasses...),
		Resolvers:  append(cfg1.Resolvers, cfg2.Resolvers...),
		Hosts:      append(cfg1.Hosts, cfg2.Hosts...),
		Ingresses:  append(cfg1.Ingresses, cfg2.Ingresses...),
		SDs:        append(cfg1.SDs, cfg2.SDs...),
		Recorders:  append(cfg1.Recorders, cfg2.Recorders...),
		Limiters:   append(cfg1.Limiters, cfg2.Limiters...),
		CLimiters:  append(cfg1.CLimiters, cfg2.CLimiters...),
		RLimiters:  append(cfg1.RLimiters, cfg2.RLimiters...),
		Loggers:    append(cfg1.Loggers, cfg2.Loggers...),
		Routers:    append(cfg1.Routers, cfg2.Routers...),
		Observers:  append(cfg1.Observers, cfg2.Observers...),
		TLS:        cfg1.TLS,
		Log:        cfg1.Log,
		API:        cfg1.API,
		Metrics:    cfg1.Metrics,
		Profiling:  cfg1.Profiling,
	}
	if cfg2.TLS != nil {
		cfg.TLS = cfg2.TLS
	}
	if cfg2.Log != nil {
		cfg.Log = cfg2.Log
	}
	if cfg2.API != nil {
		cfg.API = cfg2.API
	}
	if cfg2.Metrics != nil {
		cfg.Metrics = cfg2.Metrics
	}
	if cfg2.Profiling != nil {
		cfg.Profiling = cfg2.Profiling
	}

	return cfg
}
