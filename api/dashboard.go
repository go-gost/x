package api

import (
	"net/http"
	"strconv"

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

// getDashboardConnections returns the bounded in-process connection history.
func getDashboardConnections(c *gin.Context) {
	if !dashboard.Enabled() {
		c.Status(http.StatusNotFound)
		return
	}
	service := c.Query("service")
	sid := c.Query("sid")
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if err != nil || limit < 0 {
		c.JSON(http.StatusBadRequest, Response{Msg: "limit must be a non-negative integer"})
		return
	}
	if limit > 1000 {
		limit = 1000
	}
	c.JSON(http.StatusOK, dashboard.Default().Connections(limit, service, sid))
}

