package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/cmd"
	xmd "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

var (
	defaultParser = &parser{}
)

// Init stores the parsed CLI arguments so that subsequent calls to Parse can
// merge them with config-file and environment-variable sources.
func Init(args Args) {
	defaultParser = &parser{
		args: args,
	}
}

// Parse reads configuration from the sources specified during Init (config
// file, CLI services/nodes, and environment variables) and returns a merged
// Config ready for loading.
func Parse() (*config.Config, error) {
	return defaultParser.Parse()
}

// Args holds the raw CLI flags and positional arguments that Init will merge
// into the final configuration.
type Args struct {
	// CfgFiles is the list of YAML or JSON config sources: file paths,
	// HTTP(S) URLs, "-" for stdin, or an inline JSON string.
	// Multiple sources are merged left-to-right.
	CfgFiles []string

	// Services is the list of service definitions from -L flags.
	Services []string

	// Nodes is the list of chain-node definitions from -F flags.
	Nodes []string

	// Debug toggles debug-level logging.
	Debug bool

	// Trace toggles trace-level logging (supersedes Debug).
	Trace bool

	// ApiAddr is the address for the HTTP API server.
	ApiAddr string

	// MetricsAddr is the address for the Prometheus metrics endpoint.
	MetricsAddr string
}

type parser struct {
	args Args
}

func (p *parser) Parse() (*config.Config, error) {
	cfg := &config.Config{}

	for _, cfgFile := range p.args.CfgFiles {
		cfgFile = strings.TrimSpace(cfgFile)
		if cfgFile == "" {
			continue
		}
		fcfg, err := readConfig(cfgFile)
		if err != nil {
			return nil, err
		}
		cfg = mergeConfig(cfg, fcfg)
	}

	cmdCfg, err := cmd.BuildConfigFromCmd(p.args.Services, p.args.Nodes)
	if err != nil {
		return nil, err
	}
	cfg = mergeConfig(cfg, cmdCfg)

	if len(cfg.Services) == 0 && p.args.ApiAddr == "" && cfg.API == nil &&
		len(p.args.CfgFiles) == 0 {
		if err := cfg.Load(); err != nil {
			return nil, err
		}
	}

	if v := os.Getenv("GOST_LOGGER_LEVEL"); v != "" {
		if cfg.Log == nil {
			cfg.Log = &config.LogConfig{}
		}
		cfg.Log.Level = v
	}
	if v := os.Getenv("GOST_API"); v != "" {
		if cfg.API == nil {
			cfg.API = &config.APIConfig{}
		}
		cfg.API.Addr = v
	}
	if v := os.Getenv("GOST_METRICS"); v != "" {
		if cfg.Metrics == nil {
			cfg.Metrics = &config.MetricsConfig{}
		}
		cfg.Metrics.Addr = v
	}
	if v := os.Getenv("GOST_PROFILING"); v != "" {
		if cfg.Profiling == nil {
			cfg.Profiling = &config.ProfilingConfig{}
		}
		cfg.Profiling.Addr = v
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

// readConfig reads a single configuration source, which may be "-" (stdin),
// an HTTP(S) URL, an inline JSON string starting with "{", or a file path.
func readConfig(cfgFile string) (*config.Config, error) {
	cfg := &config.Config{}

	if cfgFile == "-" { // stdin
		br := bufio.NewReader(os.Stdin)
		b, err := br.Peek(1)
		if err != nil {
			return nil, err
		}
		if b[0] == '{' {
			if err := cfg.Read(br, "json"); err != nil {
				return nil, err
			}
		} else {
			if err := cfg.Read(br, "yaml"); err != nil {
				return nil, err
			}
		}
	} else if strings.HasPrefix(cfgFile, "{") && strings.HasSuffix(cfgFile, "}") { // inline
		if err := json.Unmarshal([]byte(cfgFile), cfg); err != nil {
			return nil, err
		}
	} else if isHTTPURL(cfgFile) { // URL
		if err := readConfigFromURL(cfgFile, cfg); err != nil {
			return nil, err
		}
	} else {
		if err := cfg.ReadFile(cfgFile); err != nil { // file
			return nil, err
		}
	}

	return cfg, nil
}

// isHTTPURL reports whether s is an HTTP or HTTPS URL.
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != "" &&
		(u.Scheme == "http" || u.Scheme == "https")
}

// maxConfigSize is the maximum response body size for remote config files.
const maxConfigSize = 10 << 20 // 10 MiB

// sharedHTTPClient is reused across config URL fetches to benefit from
// connection pooling.
var sharedHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// readConfigFromURL fetches a configuration from an HTTP(S) URL and reads it
// into cfg. The format (yaml or json) is detected from the Content-Type header
// or the URL path extension.
func readConfigFromURL(urlStr string, cfg *config.Config) error {
	resp, err := sharedHTTPClient.Get(urlStr)
	if err != nil {
		return fmt.Errorf("fetch config from %s: %w", sanitizeURL(urlStr), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // drain body for connection reuse; ignore error since we are already failing
		return fmt.Errorf("fetch config from %s: %s", sanitizeURL(urlStr), resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigSize+1))
	if err != nil {
		return fmt.Errorf("read config from %s: %w", sanitizeURL(urlStr), err)
	}
	if len(data) > maxConfigSize {
		return fmt.Errorf("config from %s exceeds maximum size %d", sanitizeURL(urlStr), maxConfigSize)
	}

	format := detectFormat(resp.Header.Get("Content-Type"), urlStr)

	if err := cfg.Read(bytes.NewReader(data), format); err != nil {
		return fmt.Errorf("parse config from %s: %w", sanitizeURL(urlStr), err)
	}
	return nil
}

// sanitizeURL returns the URL with any embedded userinfo stripped for safe
// use in error messages.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	return u.String()
}

// detectFormat determines the config format from the HTTP Content-Type header
// or the URL path extension. Returns "yaml" or "json".
func detectFormat(contentType, urlStr string) string {
	if mediatype, _, err := mime.ParseMediaType(contentType); err == nil {
		switch mediatype {
		case "application/json":
			return "json"
		case "application/yaml", "application/x-yaml",
			"text/yaml", "text/x-yaml":
			return "yaml"
		}
	}

	if u, err := url.Parse(urlStr); err == nil {
		switch strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), ".")) {
		case "json":
			return "json"
		case "yaml", "yml":
			return "yaml"
		}
	}

	return "yaml"
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
		Rewriters:  append(cfg1.Rewriters, cfg2.Rewriters...),
		Limiters:   append(cfg1.Limiters, cfg2.Limiters...),
		Quotas:     append(cfg1.Quotas, cfg2.Quotas...),
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
