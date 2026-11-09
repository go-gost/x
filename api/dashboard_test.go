package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/observer"
	dashboard "github.com/go-gost/x/dashboard"
	xstats "github.com/go-gost/x/observer/stats"
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
