package parser

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-gost/x/config"
)

func TestMergeConfig_NilBoth(t *testing.T) {
	got := mergeConfig(nil, nil)
	if got != nil {
		t.Fatal("expected nil for two nil inputs")
	}
}

func TestMergeConfig_NilFirst(t *testing.T) {
	cfg2 := &config.Config{
		Services: []*config.ServiceConfig{{Name: "svc"}},
	}
	got := mergeConfig(nil, cfg2)
	if len(got.Services) != 1 || got.Services[0].Name != "svc" {
		t.Fatal("expected cfg2 to be returned when cfg1 is nil")
	}
}

func TestMergeConfig_NilSecond(t *testing.T) {
	cfg1 := &config.Config{
		Services: []*config.ServiceConfig{{Name: "svc"}},
	}
	got := mergeConfig(cfg1, nil)
	if len(got.Services) != 1 || got.Services[0].Name != "svc" {
		t.Fatal("expected cfg1 to be returned when cfg2 is nil")
	}
}

func TestMergeConfig_AppendsAllSlices(t *testing.T) {
	cfg1 := &config.Config{
		Services:   []*config.ServiceConfig{{Name: "s1"}},
		Chains:     []*config.ChainConfig{{Name: "c1"}},
		Hops:       []*config.HopConfig{{Name: "h1"}},
		Authers:    []*config.AutherConfig{{Name: "a1"}},
		Admissions: []*config.AdmissionConfig{{Name: "ad1"}},
		Bypasses:   []*config.BypassConfig{{Name: "b1"}},
		Resolvers:  []*config.ResolverConfig{{Name: "r1"}},
		Hosts:      []*config.HostsConfig{{Name: "hosts1"}},
		Ingresses:  []*config.IngressConfig{{Name: "i1"}},
		SDs:        []*config.SDConfig{{Name: "sd1"}},
		Recorders:  []*config.RecorderConfig{{Name: "rec1"}},
		Limiters:   []*config.LimiterConfig{{Name: "l1"}},
		Quotas:     []*config.QuotaConfig{{Name: "q1"}},
		CLimiters:  []*config.LimiterConfig{{Name: "cl1"}},
		RLimiters:  []*config.LimiterConfig{{Name: "rl1"}},
		Loggers:    []*config.LoggerConfig{{Name: "log1"}},
		Routers:    []*config.RouterConfig{{Name: "rt1"}},
		Observers:  []*config.ObserverConfig{{Name: "obs1"}},
	}
	cfg2 := &config.Config{
		Services:   []*config.ServiceConfig{{Name: "s2"}},
		Chains:     []*config.ChainConfig{{Name: "c2"}},
		Hops:       []*config.HopConfig{{Name: "h2"}},
		Authers:    []*config.AutherConfig{{Name: "a2"}},
		Admissions: []*config.AdmissionConfig{{Name: "ad2"}},
		Bypasses:   []*config.BypassConfig{{Name: "b2"}},
		Resolvers:  []*config.ResolverConfig{{Name: "r2"}},
		Hosts:      []*config.HostsConfig{{Name: "hosts2"}},
		Ingresses:  []*config.IngressConfig{{Name: "i2"}},
		SDs:        []*config.SDConfig{{Name: "sd2"}},
		Recorders:  []*config.RecorderConfig{{Name: "rec2"}},
		Limiters:   []*config.LimiterConfig{{Name: "l2"}},
		Quotas:     []*config.QuotaConfig{{Name: "q2"}},
		CLimiters:  []*config.LimiterConfig{{Name: "cl2"}},
		RLimiters:  []*config.LimiterConfig{{Name: "rl2"}},
		Loggers:    []*config.LoggerConfig{{Name: "log2"}},
		Routers:    []*config.RouterConfig{{Name: "rt2"}},
		Observers:  []*config.ObserverConfig{{Name: "obs2"}},
	}

	got := mergeConfig(cfg1, cfg2)

	if len(got.Services) != 2 || got.Services[0].Name != "s1" || got.Services[1].Name != "s2" {
		t.Fatal("services not properly appended")
	}
	if len(got.Chains) != 2 {
		t.Fatal("chains not properly appended")
	}
	if len(got.Hops) != 2 {
		t.Fatal("hops not properly appended")
	}
	if len(got.Authers) != 2 {
		t.Fatal("authers not properly appended")
	}
	if len(got.Admissions) != 2 {
		t.Fatal("admissions not properly appended")
	}
	if len(got.Bypasses) != 2 {
		t.Fatal("bypasses not properly appended")
	}
	if len(got.Resolvers) != 2 {
		t.Fatal("resolvers not properly appended")
	}
	if len(got.Hosts) != 2 {
		t.Fatal("hosts not properly appended")
	}
	if len(got.Ingresses) != 2 {
		t.Fatal("ingresses not properly appended")
	}
	if len(got.SDs) != 2 {
		t.Fatal("SDs not properly appended")
	}
	if len(got.Recorders) != 2 {
		t.Fatal("recorders not properly appended")
	}
	if len(got.Limiters) != 2 {
		t.Fatal("limiters not properly appended")
	}
	if len(got.Quotas) != 2 {
		t.Fatal("quotas not properly appended")
	}
	if len(got.CLimiters) != 2 {
		t.Fatal("climiters not properly appended")
	}
	if len(got.RLimiters) != 2 {
		t.Fatal("rlimiters not properly appended")
	}
	if len(got.Loggers) != 2 {
		t.Fatal("loggers not properly appended")
	}
	if len(got.Routers) != 2 {
		t.Fatal("routers not properly appended")
	}
	if len(got.Observers) != 2 {
		t.Fatal("observers not properly appended")
	}
}

func TestMergeConfig_ScalarOverrides(t *testing.T) {
	cfg1 := &config.Config{
		TLS:       &config.TLSConfig{ServerName: "old"},
		Log:       &config.LogConfig{Level: "info"},
		API:       &config.APIConfig{Addr: ":8080"},
		Metrics:   &config.MetricsConfig{Addr: ":9090"},
		Profiling: &config.ProfilingConfig{Addr: ":6060"},
	}
	cfg2 := &config.Config{
		TLS:       &config.TLSConfig{ServerName: "new"},
		Log:       &config.LogConfig{Level: "debug"},
		API:       &config.APIConfig{Addr: ":8081"},
		Metrics:   &config.MetricsConfig{Addr: ":9091"},
		Profiling: &config.ProfilingConfig{Addr: ":6061"},
	}

	got := mergeConfig(cfg1, cfg2)

	if got.TLS.ServerName != "new" {
		t.Fatalf("TLS not overridden: got %q, want %q", got.TLS.ServerName, "new")
	}
	if got.Log.Level != "debug" {
		t.Fatalf("Log not overridden: got %q, want %q", got.Log.Level, "debug")
	}
	if got.API.Addr != ":8081" {
		t.Fatalf("API not overridden: got %q, want %q", got.API.Addr, ":8081")
	}
	if got.Metrics.Addr != ":9091" {
		t.Fatalf("Metrics not overridden: got %q, want %q", got.Metrics.Addr, ":9091")
	}
	if got.Profiling.Addr != ":6061" {
		t.Fatalf("Profiling not overridden: got %q, want %q", got.Profiling.Addr, ":6061")
	}
}

func TestMergeConfig_ScalarKeepsCfg1WhenCfg2Nil(t *testing.T) {
	cfg1 := &config.Config{
		TLS:       &config.TLSConfig{ServerName: "keep"},
		Log:       &config.LogConfig{Level: "warn"},
		API:       &config.APIConfig{Addr: ":8080"},
		Metrics:   &config.MetricsConfig{Addr: ":9090"},
		Profiling: &config.ProfilingConfig{Addr: ":6060"},
	}
	cfg2 := &config.Config{} // all scalars nil

	got := mergeConfig(cfg1, cfg2)

	if got.TLS.ServerName != "keep" {
		t.Fatal("TLS should be kept from cfg1")
	}
	if got.Log.Level != "warn" {
		t.Fatal("Log should be kept from cfg1")
	}
	if got.API.Addr != ":8080" {
		t.Fatal("API should be kept from cfg1")
	}
	if got.Metrics.Addr != ":9090" {
		t.Fatal("Metrics should be kept from cfg1")
	}
	if got.Profiling.Addr != ":6060" {
		t.Fatal("Profiling should be kept from cfg1")
	}
}

func TestInit(t *testing.T) {
	Init(Args{
		CfgFiles:    []string{"test.yml"},
		Services:    []string{"s1"},
		Nodes:       []string{"n1"},
		Debug:       true,
		Trace:       false,
		ApiAddr:     ":8080",
		MetricsAddr: ":9090",
	})

	if len(defaultParser.args.CfgFiles) != 1 || defaultParser.args.CfgFiles[0] != "test.yml" {
		t.Fatalf("CfgFiles not set: got %v", defaultParser.args.CfgFiles)
	}
	if len(defaultParser.args.Services) != 1 || defaultParser.args.Services[0] != "s1" {
		t.Fatal("Services not set")
	}
	if len(defaultParser.args.Nodes) != 1 || defaultParser.args.Nodes[0] != "n1" {
		t.Fatal("Nodes not set")
	}
	if !defaultParser.args.Debug {
		t.Fatal("Debug not set")
	}
	if defaultParser.args.Trace {
		t.Fatal("Trace should be false")
	}
	if defaultParser.args.ApiAddr != ":8080" {
		t.Fatal("ApiAddr not set")
	}
	if defaultParser.args.MetricsAddr != ":9090" {
		t.Fatal("MetricsAddr not set")
	}
}

func TestParse_MultiFile(t *testing.T) {
	// Create two temporary config files.
	cfg1 := &config.Config{
		Services: []*config.ServiceConfig{{Name: "s1", Addr: ":8080"}},
	}
	cfg2 := &config.Config{
		Services: []*config.ServiceConfig{{Name: "s2", Addr: ":8081"}},
		Log:      &config.LogConfig{Level: "debug"},
		Quotas:   []*config.QuotaConfig{{Name: "q1"}},
	}

	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "cfg1.yml")
	file2 := filepath.Join(tmpDir, "cfg2.yml")

	for _, entry := range []struct {
		path string
		cfg  *config.Config
	}{
		{file1, cfg1},
		{file2, cfg2},
	} {
		f, err := os.Create(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := entry.cfg.Write(f, "yaml"); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}

	Init(Args{
		CfgFiles: []string{file1, file2},
	})

	got, err := Parse()
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}

	if len(got.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(got.Services))
	}
	if got.Log == nil || got.Log.Level != "debug" {
		t.Fatal("Log.Level not set from cfg2")
	}
	if len(got.Quotas) != 1 || got.Quotas[0].Name != "q1" {
		t.Fatal("Quotas not merged from cfg2")
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"http://example.com/config.yaml", true},
		{"https://example.com/config.json", true},
		{"ftp://example.com/config.yaml", false},
		{"config.yaml", false},
		{"/path/to/config.yml", false},
		{"http://[::1]:8080/cfg", true},
	}
	for _, tt := range tests {
		if got := isHTTPURL(tt.input); got != tt.expected {
			t.Errorf("isHTTPURL(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		contentType string
		url         string
		want        string
	}{
		{"", "http://example.com/config.json", "json"},
		{"", "http://example.com/config.yml", "yaml"},
		{"", "http://example.com/config.yaml", "yaml"},
		{"", "http://example.com/config", "yaml"}, // default
		{"application/json", "http://example.com/config", "json"},
		{"application/yaml", "http://example.com/config", "yaml"},
		{"application/x-yaml", "http://example.com/config", "yaml"},
		{"text/yaml", "http://example.com/config", "yaml"},
		{"text/x-yaml", "http://example.com/config", "yaml"},
		{"text/plain; charset=utf-8", "http://example.com/config.json", "json"}, // content-type ignored, extension wins
		{"text/plain", "http://example.com/config", "yaml"},                     // unknown -> default
	}
	for _, tt := range tests {
		if got := detectFormat(tt.contentType, tt.url); got != tt.want {
			t.Errorf("detectFormat(%q, %q) = %q, want %q", tt.contentType, tt.url, got, tt.want)
		}
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://user:pass@example.com/path", "http://example.com/path"},
		{"https://example.com/path", "https://example.com/path"},
		{"not a url", "not%20a%20url"},
		{"http://user@example.com/path", "http://example.com/path"}, // user with no password
	}
	for _, tt := range tests {
		if got := sanitizeURL(tt.input); got != tt.expected {
			t.Errorf("sanitizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestReadConfigFromURL_YAML(t *testing.T) {
	// Write a YAML config and serve it via httptest.
	cfg := &config.Config{
		Services: []*config.ServiceConfig{{Name: "svc", Addr: ":8080"}},
		Log:      &config.LogConfig{Level: "debug"},
	}
	var buf bytes.Buffer
	if err := cfg.Write(&buf, "yaml"); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(body)
	}))
	defer ts.Close()

	got := &config.Config{}
	if err := readConfigFromURL(ts.URL, got); err != nil {
		t.Fatalf("readConfigFromURL: %v", err)
	}
	if len(got.Services) != 1 || got.Services[0].Name != "svc" {
		t.Fatalf("unexpected services: %+v", got.Services)
	}
	if got.Log == nil || got.Log.Level != "debug" {
		t.Fatalf("unexpected log: %+v", got.Log)
	}
}

func TestReadConfigFromURL_JSON(t *testing.T) {
	// Remote serving JSON with explicit Content-Type.
	cfg := &config.Config{
		Services: []*config.ServiceConfig{{Name: "json-svc", Addr: ":9090"}},
	}
	var buf bytes.Buffer
	if err := cfg.Write(&buf, "json"); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer ts.Close()

	got := &config.Config{}
	if err := readConfigFromURL(ts.URL, got); err != nil {
		t.Fatalf("readConfigFromURL: %v", err)
	}
	if got.Services[0].Name != "json-svc" {
		t.Fatalf("unexpected service name: %s", got.Services[0].Name)
	}
}

func TestReadConfigFromURL_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	err := readConfigFromURL(ts.URL, &config.Config{})
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestReadConfigFromURL_OverSize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(make([]byte, maxConfigSize+1))
	}))
	defer ts.Close()

	err := readConfigFromURL(ts.URL, &config.Config{})
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
}

func TestParse_FileAndURL(t *testing.T) {
	// Create a local file.
	fileCfg := &config.Config{
		Services: []*config.ServiceConfig{{Name: "file-svc", Addr: ":8080"}},
	}
	tmpDir := t.TempDir()
	f, err := os.Create(filepath.Join(tmpDir, "local.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fileCfg.Write(f, "yaml"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	// Serve a second config over HTTP.
	urlCfg := &config.Config{
		Services: []*config.ServiceConfig{{Name: "url-svc", Addr: ":8081"}},
		Log:      &config.LogConfig{Level: "debug"},
	}
	var buf bytes.Buffer
	if err := urlCfg.Write(&buf, "yaml"); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(body)
	}))
	defer ts.Close()

	Init(Args{
		CfgFiles: []string{filepath.Join(tmpDir, "local.yml"), ts.URL},
	})

	got, err := Parse()
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	if len(got.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(got.Services))
	}
	if got.Log == nil || got.Log.Level != "debug" {
		t.Fatal("Log.Level not set from URL config")
	}
}
