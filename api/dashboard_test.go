package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/config"
	dashboard "github.com/go-gost/x/dashboard"
	xchain "github.com/go-gost/x/chain"
	xlogger "github.com/go-gost/x/logger"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/registry"
)

type stubAuther struct{}

func (stubAuther) Authenticate(context.Context, string, string, ...auth.Option) (string, bool) {
	return "", false
}

func newDashboardRouter(t *testing.T, auther auth.Authenticator) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, &Options{Auther: auther})
	return r
}

func TestDashboardSnapshotNotFoundWhenDisabled(t *testing.T) {
	dashboard.Enable(false)
	r := newDashboardRouter(t, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/snapshot", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestDashboardSnapshotEnabled(t *testing.T) {
	dashboard.Enable(true)
	defer dashboard.Enable(false)

	_ = dashboard.Default().Observe(context.Background(), []observer.Event{
		xstats.StatsEvent{Kind: "service", Service: "svc", InputBytes: 1},
	})

	r := newDashboardRouter(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/snapshot", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"svc"`) {
		t.Fatalf("body does not contain service: %s", w.Body.String())
	}
}

func TestCreateBypassIsWrapped(t *testing.T) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))

	oldCfg := config.Global()
	config.Set(&config.Config{})
	t.Cleanup(func() {
		registry.BypassRegistry().Unregister("api-bp")
		config.Set(oldCfg)
		dashboard.Enable(false)
		dashboard.ResetState()
	})

	dashboard.ResetState()
	dashboard.Enable(true)

	r := newDashboardRouter(t, nil)
	body := `{"name":"api-bp","matchers":["127.0.0.1"]}`
	req := httptest.NewRequest(http.MethodPost, "/config/bypasses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	bp := registry.BypassRegistry().Get("api-bp")
	if bp == nil {
		t.Fatal("bypass not registered")
	}
	bp.Contains(context.Background(), "tcp", "127.0.0.1", bypass.WithService("svc"))
	dashboard.Flush()

	for _, m := range dashboard.Default().Snapshot().Modules {
		if m.Kind == "bypass" && m.Name == "api-bp" && m.Service == "svc" && m.Stats.Calls == 1 {
			return
		}
	}
	t.Fatal("API-created bypass is not instrumented")
}

func TestDashboardSnapshotRequiresAuth(t *testing.T) {
	dashboard.Enable(true)
	defer dashboard.Enable(false)

	r := newDashboardRouter(t, stubAuther{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/snapshot", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestChainMutationsRefreshDashboardFilter(t *testing.T) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))

	oldCfg := config.Global()
	config.Set(&config.Config{})
	dashboard.Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	t.Cleanup(func() {
		registry.ChainRegistry().Unregister("api-chain")
		dashboard.Apply(nil)
		config.Set(oldCfg)
		dashboard.ResetState()
	})

	r := newDashboardRouter(t, nil)
	body := `{"name":"api-chain","hops":[]}`
	req := httptest.NewRequest(http.MethodPost, "/config/chains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", w.Code, w.Body.String())
	}

	xchain.ChainRecorded("api-chain", 0, "node-api", time.Millisecond, nil)
	if _, ok := dashboard.Default().Snapshot().Chains["api-chain"]; !ok {
		t.Fatal("API-created chain was filtered out")
	}

	req = httptest.NewRequest(http.MethodDelete, "/config/chains/api-chain", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", w.Code, w.Body.String())
	}

	xchain.ChainRecorded("api-chain", 0, "node-api", time.Millisecond, nil)
	if _, ok := dashboard.Default().Snapshot().Chains["api-chain"]; ok {
		t.Fatal("API-deleted chain still visible")
	}
}

func TestConnectionsReturnsNewestFirst(t *testing.T) {
	dashboard.ResetState()
	dashboard.Enable(true)
	defer dashboard.Enable(false)

	dashboard.Default().RecordConnection(dashboard.ConnectionRecord{
		SID: "c-old", Service: "svc", RemoteAddr: "10.0.0.1:80", Time: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
	})
	dashboard.Default().RecordConnection(dashboard.ConnectionRecord{
		SID: "c-new", Service: "svc", RemoteAddr: "10.0.0.2:80", Time: time.Now().UTC().Format(time.RFC3339),
	})

	r := newDashboardRouter(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/connections?service=svc", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"c-new"`) {
		t.Fatalf("newest record missing: %s", w.Body.String())
	}
	if idx := strings.Index(w.Body.String(), `"c-old"`); idx < 0 {
		t.Fatalf("newest record missing: %s", w.Body.String())
	}
	if !(strings.Index(w.Body.String(), `"c-new"`) < strings.Index(w.Body.String(), `"c-old"`)) {
		t.Fatalf("records are not newest-first: %s", w.Body.String())
	}
}

func TestConnectionsFiltersByService(t *testing.T) {
	dashboard.ResetState()
	dashboard.Enable(true)
	defer dashboard.Enable(false)

	for _, s := range []string{"a", "b", "a"} {
		dashboard.Default().RecordConnection(dashboard.ConnectionRecord{
			SID: s, Service: "s-" + s, RemoteAddr: "10.0.0.1:80", Time: time.Now().UTC().Format(time.RFC3339),
		})
	}
	r := newDashboardRouter(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/connections?service=s-a", nil))
	got := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(got, `"s-b"`) {
		t.Fatalf("unrelated service leaked: %s", got)
	}
}

func TestConnections404WhenDisabled(t *testing.T) {
	dashboard.Enable(false)
	r := newDashboardRouter(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/connections", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestConnectionsLimitCapped(t *testing.T) {
	dashboard.ResetState()
	dashboard.Enable(true)
	defer dashboard.Enable(false)

	for i := 0; i < 5; i++ {
		dashboard.Default().RecordConnection(dashboard.ConnectionRecord{
			SID: fmt.Sprintf("s-%d", i), Service: "svc", RemoteAddr: "10.0.0.1:80", Time: time.Now().UTC().Format(time.RFC3339),
		})
	}
	r := newDashboardRouter(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard/connections?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	count := strings.Count(w.Body.String(), `"sid"`)
	if count > 2 {
		t.Fatalf("limit=2 ignored: %s", w.Body.String())
	}
}

