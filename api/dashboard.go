package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/dashboard"
)

// getDashboardSnapshot returns the dashboard read model. The route is always
// registered so the SPA gets a stable 404 when the feature is disabled.
func getDashboardSnapshot(c *gin.Context) {
	if !dashboard.Enabled() {
		c.Status(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, dashboard.Default().Snapshot())
}
